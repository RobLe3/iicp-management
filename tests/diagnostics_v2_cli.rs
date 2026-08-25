use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn assessment(now: u64) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        serde_json::to_vec(&json!({
            "schema_version":"iicp.management-bootstrap-assessment.v1",
            "assessment_id":"assessment:runtime-diagnostic",
            "environment_mode":"local_only",
            "observed_at":now-1,
            "expires_at":now+300,
            "readiness":"ready_for_proposal",
            "authorizes_mutation":false,
            "observations":[], "recommendations":[], "required_decisions":[]
        }))
        .unwrap(),
    )
    .unwrap();
    file
}

#[test]
fn diagnostics_v2_accepts_file_and_stdin_and_v1_remains_default() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let assessment = assessment(now);
    let runtime = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        runtime.path(),
        include_bytes!("../fixtures/runtime-health-ready-v1.json"),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("diagnostic.json");
    let status = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "diagnostics",
            "create",
            assessment.path().to_str().unwrap(),
            "--runtime-health",
            runtime.path().to_str().unwrap(),
            "--runtime-target",
            "node:private",
            "--output",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let value: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(
        value["schema_version"],
        "iicp.management-diagnostic-bundle.v2"
    );
    let text = serde_json::to_string(&value).unwrap();
    assert!(!text.contains("node:private"));

    let out2 = dir.path().join("diagnostic-stdin.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "diagnostics",
            "create",
            assessment.path().to_str().unwrap(),
            "--runtime-health",
            "-",
            "--runtime-target",
            "node:stdin",
            "--output",
            out2.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(include_bytes!("../fixtures/runtime-health-ready-v1.json"))
        .unwrap();
    assert!(child.wait().unwrap().success());

    let out3 = dir.path().join("diagnostic-v1.json");
    assert!(Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "diagnostics",
            "create",
            assessment.path().to_str().unwrap(),
            "--output",
            out3.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    let legacy: Value = serde_json::from_slice(&std::fs::read(&out3).unwrap()).unwrap();
    assert_eq!(
        legacy["schema_version"],
        "iicp.management-diagnostic-bundle.v1"
    );
}
