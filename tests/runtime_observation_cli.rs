use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn sample() -> &'static [u8] {
    include_bytes!("../fixtures/runtime-health-ready-v1.json")
}

#[test]
fn cli_reads_file_and_stdin_and_emits_typed_non_authorizing_json() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), sample()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "show",
            "runtime-health",
            file.path().to_str().unwrap(),
            "--target",
            "node:test",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["schema_version"],
        "iicp.management-runtime-observation.v1"
    );
    assert_eq!(value["authorizes_mutation"], false);

    let mut child = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "show",
            "runtime-health",
            "-",
            "--target",
            "node:test",
            "--brief",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(sample()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("mutation not authorized"));
}
