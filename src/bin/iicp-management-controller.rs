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
fn serve(_: Controller, _: &Path) -> Result<(), String> {
    Err("local IPC transport is not implemented on this platform".into())
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
