use iicp_management_core::controller::{Controller, ControllerPolicy, ManagementRequest};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{BufRead, BufReader, Write},
    path::Path,
};

fn open(db: &Path, key: &Path, audience: String, domain: String) -> Result<Controller, String> {
    let bytes = fs::read(key).map_err(|e| e.to_string())?;
    let key =
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "public key must be 32 raw bytes")?;
    Controller::open(
        db,
        ControllerPolicy {
            audience,
            domain,
            allowed_actions: BTreeSet::from(["apply".into(), "observe".into(), "rollback".into()]),
            revocation_checkpoint: Controller::now(),
            max_checkpoint_age: 3600,
            high_impact_actions: BTreeSet::from(["apply".into(), "rollback".into()]),
            max_decision_events: 10_000,
        },
        key,
    )
    .map_err(|e| e.to_string())
}
fn process(controller: &mut Controller, line: &str) -> String {
    match serde_json::from_str::<ManagementRequest>(line)
        .map_err(|_| "REQUEST_INVALID:json".to_string())
        .and_then(|r| {
            controller
                .evaluate(&r, Controller::now())
                .map_err(|e| e.to_string())
        }) {
        Ok(r) => serde_json::to_string(&r).unwrap(),
        Err(e) => serde_json::json!({"decision":"rejected","reason":e}).to_string(),
    }
}
#[cfg(unix)]
fn serve(mut controller: Controller, socket: &Path) -> Result<(), String> {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let _ = fs::remove_file(socket);
    let listener = UnixListener::bind(socket).map_err(|e| e.to_string())?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(stream.try_clone().map_err(|e| e.to_string())?)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        writeln!(stream, "{}", process(&mut controller, &line)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
#[cfg(not(unix))]
#[cfg(not(windows))]
fn serve(_: Controller, _: &Path) -> Result<(), String> {
    Err("local IPC transport is not implemented on this platform".into())
}

#[cfg(windows)]
fn serve(mut controller: Controller, pipe: &Path) -> Result<(), String> {
    windows_ipc::serve(&mut controller, pipe)
}

#[cfg(windows)]
mod windows_ipc {
    use super::{process, Controller};
    use std::{ffi::c_void, mem::size_of, path::Path, ptr};
    use windows_sys::{
        core::PWSTR,
        Win32::{
            Foundation::{
                CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER,
                ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
            },
            Security::{
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    SDDL_REVISION_1,
                },
                GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
            },
            Storage::FileSystem::{ReadFile, WriteFile, PIPE_ACCESS_DUPLEX},
            System::{
                Pipes::{
                    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
                    PIPE_TYPE_BYTE, PIPE_WAIT,
                },
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        },
    };

    const MAX_REQUEST_BYTES: usize = 1024 * 1024;

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalAllocation(*mut c_void);
    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn current_user_sid() -> Result<String, String> {
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("OpenProcessToken failed: {}", GetLastError()));
            }
            let token = Handle(token);
            let mut needed = 0;
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
            if needed == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
                return Err(format!(
                    "GetTokenInformation size failed: {}",
                    GetLastError()
                ));
            }
            let mut buffer = vec![0u8; needed as usize];
            if GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            ) == 0
            {
                return Err(format!("GetTokenInformation failed: {}", GetLastError()));
            }
            let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid_text: PWSTR = ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
                return Err(format!("ConvertSidToStringSidW failed: {}", GetLastError()));
            }
            let sid_text_allocation = LocalAllocation(sid_text.cast());
            let mut length = 0;
            while *sid_text.add(length) != 0 {
                length += 1;
            }
            let result = String::from_utf16(std::slice::from_raw_parts(sid_text, length))
                .map_err(|_| "current-user SID is not valid UTF-16".to_string());
            drop(sid_text_allocation);
            result
        }
    }

    fn owner_sddl() -> Result<String, String> {
        let sid = current_user_sid()?;
        // Protected DACL: only the current user and LocalSystem receive full access.
        Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
    }

    fn owner_security_descriptor() -> Result<LocalAllocation, String> {
        let sddl = wide(&owner_sddl()?);
        let mut descriptor = ptr::null_mut();
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err(format!(
                    "security descriptor creation failed: {}",
                    GetLastError()
                ));
            }
        }
        Ok(LocalAllocation(descriptor))
    }

    fn read_request(pipe: HANDLE) -> Result<String, String> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut read = 0;
            let ok = unsafe {
                ReadFile(
                    pipe,
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(format!("named-pipe read failed: {}", unsafe {
                    GetLastError()
                }));
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read as usize]);
            if bytes.len() > MAX_REQUEST_BYTES {
                return Err("named-pipe request exceeds 1 MiB".into());
            }
            if bytes.contains(&b'\n') {
                break;
            }
        }
        String::from_utf8(bytes).map_err(|_| "named-pipe request is not UTF-8".into())
    }

    fn write_response(pipe: HANDLE, response: &str) -> Result<(), String> {
        let bytes = format!("{response}\n").into_bytes();
        let mut offset = 0;
        while offset < bytes.len() {
            let mut written = 0;
            let ok = unsafe {
                WriteFile(
                    pipe,
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as u32,
                    &mut written,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || written == 0 {
                return Err(format!("named-pipe write failed: {}", unsafe {
                    GetLastError()
                }));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn checked_pipe_name(path: &Path) -> Result<Vec<u16>, String> {
        let name = path.to_str().ok_or("named-pipe path is not valid UTF-8")?;
        if !name.starts_with(r"\\.\pipe\") || name.len() <= r"\\.\pipe\".len() {
            return Err(r"Windows IPC path must use \\.\pipe\<name>".into());
        }
        Ok(wide(name))
    }

    fn serve_one(controller: &mut Controller, name: &[u16]) -> Result<(), String> {
        let descriptor = owner_security_descriptor()?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };

        let raw = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                &mut attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(format!("named-pipe creation failed: {}", unsafe {
                GetLastError()
            }));
        }
        let pipe = Handle(raw);
        let connected = unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            return Err(format!("named-pipe connection failed: {}", unsafe {
                GetLastError()
            }));
        }
        let response = match read_request(pipe.0) {
            Ok(request) => process(controller, &request),
            Err(error) => serde_json::json!({
                "decision": "rejected",
                "reason": format!("REQUEST_INVALID:{error}")
            })
            .to_string(),
        };
        write_response(pipe.0, &response)?;
        unsafe { DisconnectNamedPipe(pipe.0) };
        Ok(())
    }

    pub(super) fn serve(controller: &mut Controller, path: &Path) -> Result<(), String> {
        let name = checked_pipe_name(path)?;
        loop {
            serve_one(controller, &name)?;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::SigningKey;
        use std::{
            collections::BTreeSet,
            fs::OpenOptions,
            io::{BufRead, BufReader, Write},
            thread,
            time::Duration,
        };

        #[test]
        fn owner_descriptor_is_protected_and_has_no_broad_principal() {
            let sddl = owner_sddl().unwrap();
            assert!(sddl.starts_with("D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-"));
            assert!(!sddl.contains(";;;WD)"));
            assert!(!sddl.contains(";;;AU)"));
            owner_security_descriptor().unwrap();
        }

        #[test]
        fn current_user_can_exchange_a_request_over_the_named_pipe() {
            let directory = tempfile::tempdir().unwrap();
            let db = directory.path().join("controller.db");
            let key = SigningKey::from_bytes(&[17; 32]);
            let mut controller = Controller::open(
                &db,
                super::super::ControllerPolicy {
                    audience: "controller:test".into(),
                    domain: "domain:test".into(),
                    allowed_actions: BTreeSet::from(["apply".into()]),
                    revocation_checkpoint: Controller::now(),
                    max_checkpoint_age: 3600,
                    high_impact_actions: BTreeSet::from(["apply".into()]),
                    max_decision_events: 100,
                },
                key.verifying_key().to_bytes(),
            )
            .unwrap();
            let pipe_name = format!(r"\\.\pipe\iicp-management-test-{}", std::process::id());
            let wide_name = checked_pipe_name(Path::new(&pipe_name)).unwrap();
            let server = thread::spawn(move || serve_one(&mut controller, &wide_name).unwrap());

            let mut client = None;
            for _ in 0..100 {
                match OpenOptions::new().read(true).write(true).open(&pipe_name) {
                    Ok(stream) => {
                        client = Some(stream);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
            let mut client = client.expect("owner could not connect to named pipe");
            writeln!(client, "{{}}").unwrap();
            let mut response = String::new();
            BufReader::new(client).read_line(&mut response).unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&response).unwrap()["decision"],
                "rejected"
            );
            server.join().unwrap();
        }
    }
}
fn main() {
    let a: Vec<String> = env::args().collect();
    if a.len() != 7 || a[1] != "serve" {
        eprintln!("usage: iicp-management-controller serve <socket> <db> <public-key> <audience> <domain>");
        std::process::exit(2)
    }
    let c = open(
        Path::new(&a[3]),
        Path::new(&a[4]),
        a[5].clone(),
        a[6].clone(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    if let Err(e) = serve(c, Path::new(&a[2])) {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
