use iicp_management_core::adapters::{AdapterHost, RuntimeConfigAdapter, SyntheticAdapter};
use iicp_management_core::apply_gate::LocalApplyGateV1;
use iicp_management_core::controller::{
    ApplyAuthorizationReceiptV1, Controller, ControllerPolicy, LocalPlanSubmissionV1,
    ManagementRequest,
};
use iicp_management_core::controller::{DecisionState, PlanSubmissionReceiptV1};
use iicp_management_core::execution::{
    execute_authorized, ApplyLifecycleReceiptV1, LocalApplyExecutionV1,
};
use iicp_management_core::profile::{
    profile_digest, ManagementProfileQueryV1, ManagementProfileResponseV1,
    MANAGEMENT_PROFILE_QUERY_SCHEMA, MANAGEMENT_PROFILE_RESPONSE_SCHEMA,
};
use iicp_management_core::recovery::{
    execute_recovery_request, LocalRecoveryExecutionV1, LocalRecoveryGateV1,
};
use serde::Deserialize;
#[cfg(unix)]
use std::io::{BufRead, BufReader, Read, Write};
use std::{collections::BTreeSet, env, fs, path::Path};

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

fn open(db: &Path, key: &Path, audience: String, domain: String) -> Result<Controller, String> {
    let bytes = fs::read(key).map_err(|e| e.to_string())?;
    let key =
        <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "public key must be 32 raw bytes")?;
    Controller::open(
        db,
        ControllerPolicy {
            audience,
            domain,
            allowed_actions: BTreeSet::from([
                "accept_plan".into(),
                "apply".into(),
                "observe".into(),
                "rollback".into(),
                "compensate".into(),
                "safe".into(),
            ]),
            revocation_checkpoint: Controller::now(),
            max_checkpoint_age: 3600,
            high_impact_actions: BTreeSet::from([
                "accept_plan".into(),
                "apply".into(),
                "rollback".into(),
                "compensate".into(),
                "safe".into(),
            ]),
            max_decision_events: 10_000,
        },
        key,
    )
    .map_err(|e| e.to_string())
}
#[derive(Deserialize)]
#[serde(untagged)]
enum WireRequest {
    Profile(ManagementProfileQueryV1),
    RecoveryExecute(Box<LocalRecoveryExecutionV1>),
    Recovery(Box<LocalRecoveryGateV1>),
    Execute(Box<LocalApplyExecutionV1>),
    Apply(Box<LocalApplyGateV1>),
    Plan(Box<LocalPlanSubmissionV1>),
    Legacy(Box<ManagementRequest>),
}

fn process(controller: &mut Controller, host: &mut Option<AdapterHost>, line: &str) -> String {
    match serde_json::from_str::<WireRequest>(line) {
        Ok(WireRequest::Profile(query)) => {
            if query.schema_version != MANAGEMENT_PROFILE_QUERY_SCHEMA {
                return serde_json::json!({"decision":"rejected","reason":"PROFILE_QUERY_INVALID"}).to_string();
            }
            let resource_kinds = host
                .as_ref()
                .map(AdapterHost::registered_capabilities)
                .unwrap_or_default();
            let profile = controller.management_profile(resource_kinds, Controller::now());
            match profile_digest(&profile, Controller::now()) {
                Ok(profile_digest) => serde_json::to_string(&ManagementProfileResponseV1 {
                    schema_version: MANAGEMENT_PROFILE_RESPONSE_SCHEMA.into(),
                    profile,
                    profile_digest,
                    source: "owner_protected_local_controller".into(),
                    authorizes_mutation: false,
                })
                .unwrap(),
                Err(reason) => serde_json::json!({"decision":"rejected","reason":reason}).to_string(),
            }
        }
        Ok(WireRequest::RecoveryExecute(execution)) => match host.as_mut() {
            Some(host) => match execute_recovery_request(controller, host, &execution, Controller::now()) {
                Ok(receipt) => serde_json::to_string(&receipt).unwrap(),
                Err(error) => serde_json::json!({"schema_version":"iicp.management-local-recovery.v1","operation_id":execution.gate.operation.operation_id,"outcome":"failed","reason":error,"safe_next_action":"REAUTHORIZE_OR_REVIEW"}).to_string(),
            },
            None => serde_json::json!({"schema_version":"iicp.management-local-recovery.v1","operation_id":execution.gate.operation.operation_id,"outcome":"failed","reason":"EXECUTOR_NOT_CONFIGURED","safe_next_action":"START_CONFIGURED_EXECUTOR"}).to_string(),
        },
        Ok(WireRequest::Recovery(gate)) => match controller.authorize_recovery_gate(&gate, Controller::now()) {
            Ok((receipt, _)) => serde_json::to_string(&receipt).unwrap(),
            Err(error) => serde_json::to_string(&ApplyAuthorizationReceiptV1::failure(
                gate.request.request_id, DecisionState::Rejected, error.to_string(), controller.generation().ok(),
            )).unwrap(),
        },
        Ok(WireRequest::Execute(execution)) => match host.as_mut() {
            Some(host) => match execute_authorized(controller, host, &execution, Controller::now())
            {
                Ok(receipt) => serde_json::to_string(&receipt).unwrap(),
                Err(error) => serde_json::to_string(&ApplyLifecycleReceiptV1::failure(
                    execution.gate.operation.operation_id.clone(),
                    error,
                ))
                .unwrap(),
            },
            None => serde_json::to_string(&ApplyLifecycleReceiptV1::failure(
                execution.gate.operation.operation_id.clone(),
                "EXECUTOR_NOT_CONFIGURED",
            ))
            .unwrap(),
        },
        Ok(WireRequest::Apply(gate)) => {
            match controller.authorize_apply_gate(&gate, Controller::now()) {
                Ok((receipt, _)) => serde_json::to_string(&receipt).unwrap(),
                Err(error) => {
                    let decision = if error.to_string() == "STORAGE_ERROR" {
                        DecisionState::Deferred
                    } else {
                        DecisionState::Rejected
                    };
                    serde_json::to_string(&ApplyAuthorizationReceiptV1::failure(
                        gate.request.request_id,
                        decision,
                        error.to_string(),
                        controller.generation().ok(),
                    ))
                    .unwrap()
                }
            }
        }
        Ok(WireRequest::Legacy(request)) => {
            if request.action == "apply" {
                return serde_json::json!({
                    "decision":"rejected",
                    "reason":"REQUEST_APPLY_GATE_REQUIRED"
                })
                .to_string();
            }
            match controller.evaluate(&request, Controller::now()) {
                Ok(receipt) => serde_json::to_string(&receipt).unwrap(),
                Err(error) => serde_json::json!({"decision":"rejected","reason":error.to_string()})
                    .to_string(),
            }
        }
        Ok(WireRequest::Plan(submission)) => {
            match controller.accept_plan_submission(&submission, Controller::now()) {
                Ok(receipt) => serde_json::to_string(&receipt).unwrap(),
                Err(error) => {
                    let decision = if error.to_string() == "STORAGE_ERROR" {
                        DecisionState::Deferred
                    } else {
                        DecisionState::Rejected
                    };
                    serde_json::to_string(&PlanSubmissionReceiptV1::failure(
                        submission.request.request_id,
                        decision,
                        error.to_string(),
                        controller.generation().ok(),
                    ))
                    .unwrap()
                }
            }
        }
        Err(_) => {
            serde_json::json!({"decision":"rejected","reason":"REQUEST_INVALID:json"}).to_string()
        }
    }
}
#[cfg(unix)]
fn bind_owner_only(socket: &Path) -> Result<std::os::unix::net::UnixListener, String> {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    // UnixListener::bind creates a socket with mode 0777 filtered by the
    // process umask. This controller is still single-threaded at startup, so
    // temporarily narrowing the umask avoids a world-readable interval before
    // chmod. The explicit chmod remains defense in depth.
    struct UmaskGuard(libc::mode_t);
    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            unsafe { libc::umask(self.0) };
        }
    }

    let guard = UmaskGuard(unsafe { libc::umask(0o177) });
    let listener = UnixListener::bind(socket).map_err(|e| e.to_string());
    drop(guard);
    let listener = listener?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    Ok(listener)
}

#[cfg(unix)]
fn serve(
    mut controller: Controller,
    mut host: Option<AdapterHost>,
    socket: &Path,
) -> Result<(), String> {
    let _ = fs::remove_file(socket);
    let listener = bind_owner_only(socket)?;
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(stream.try_clone().map_err(|e| e.to_string())?)
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        let response = if line.len() > MAX_REQUEST_BYTES {
            serde_json::json!({"decision":"rejected","reason":"REQUEST_INVALID:too_large"})
                .to_string()
        } else {
            process(&mut controller, &mut host, &line)
        };
        writeln!(stream, "{response}").map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn serve(_: Controller, _: Option<AdapterHost>, _: &Path) -> Result<(), String> {
    Err("local IPC transport is not implemented on this platform".into())
}

#[cfg(windows)]
fn serve(
    mut controller: Controller,
    mut host: Option<AdapterHost>,
    pipe: &Path,
) -> Result<(), String> {
    windows_ipc::serve(&mut controller, &mut host, pipe)
}

#[cfg(windows)]
mod windows_ipc {
    use super::{process, AdapterHost, Controller, MAX_REQUEST_BYTES};
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

    fn serve_one(
        controller: &mut Controller,
        host: &mut Option<AdapterHost>,
        name: &[u16],
    ) -> Result<(), String> {
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
            Ok(request) => process(controller, host, &request),
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

    pub(super) fn serve(
        controller: &mut Controller,
        host: &mut Option<AdapterHost>,
        path: &Path,
    ) -> Result<(), String> {
        let name = checked_pipe_name(path)?;
        loop {
            serve_one(controller, host, &name)?;
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
            let server =
                thread::spawn(move || serve_one(&mut controller, &mut None, &wide_name).unwrap());

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
    if !((a.len() == 7 && a[1] == "serve") || (a.len() >= 9 && a[1] == "serve-executor")) {
        eprintln!("usage: iicp-management-controller serve <socket> <db> <public-key> <audience> <domain>\n       iicp-management-controller serve-executor <socket> <db> <public-key> <audience> <domain> <synthetic-v1 target|runtime-config-v1 target path>");
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
    let host = if a[1] == "serve-executor" {
        let mut host = AdapterHost::new();
        match a[7].as_str() {
            "synthetic-v1" if a.len() == 9 => host.register(
                a[8].clone(),
                "synthetic-v1",
                Box::new(SyntheticAdapter::new()),
            ),
            "runtime-config-v1" if a.len() == 10 => {
                let adapter = RuntimeConfigAdapter::open(Path::new(&a[9])).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2)
                });
                host.register(a[8].clone(), "runtime-config-v1", Box::new(adapter));
            }
            _ => {
                eprintln!("invalid executor adapter configuration");
                std::process::exit(2)
            }
        }
        Some(host)
    } else {
        None
    };
    if let Err(e) = serve(c, host, Path::new(&a[2])) {
        eprintln!("{e}");
        std::process::exit(1)
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use iicp_management_core::profile::ManagementProfileResponseV1;

    fn open_test(path: &Path) -> Controller {
        let key = SigningKey::from_bytes(&[41; 32]);
        Controller::open(
            path,
            ControllerPolicy {
                audience: "controller:test".into(),
                domain: "domain:test".into(),
                allowed_actions: BTreeSet::from(["apply".into(), "observe".into()]),
                revocation_checkpoint: Controller::now(),
                max_checkpoint_age: 3600,
                high_impact_actions: BTreeSet::from(["apply".into()]),
                max_decision_events: 100,
            },
            key.verifying_key().to_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn profile_query_is_read_only_and_stable_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("controller.db");
        let request = serde_json::to_string(&ManagementProfileQueryV1 {
            schema_version: MANAGEMENT_PROFILE_QUERY_SCHEMA.into(),
        })
        .unwrap();
        let mut first_controller = open_test(&database);
        let first: ManagementProfileResponseV1 =
            serde_json::from_str(&process(&mut first_controller, &mut None, &request)).unwrap();
        assert_eq!(first_controller.generation().unwrap(), 0);
        drop(first_controller);

        let mut restarted = open_test(&database);
        let second: ManagementProfileResponseV1 =
            serde_json::from_str(&process(&mut restarted, &mut None, &request)).unwrap();
        assert_eq!(restarted.generation().unwrap(), 0);
        assert_eq!(first.profile_digest, second.profile_digest);
        assert!(!second.authorizes_mutation);
        assert_eq!(second.source, "owner_protected_local_controller");
    }
}
