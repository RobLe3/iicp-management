use iicp_client::runtime_config::{OperatingMode, RuntimeConfigV1};
use iicp_management_core::bootstrap::BOOTSTRAP_WORKFLOW_SCHEMA;
use std::process::Command;

#[test]
fn prepare_cli_is_one_step_non_authorizing_and_versioned() {
    let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), serde_json::to_vec(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "bootstrap",
            "prepare",
            file.path().to_str().unwrap(),
            "--resource-id",
            "runtime:local",
            "--operator-id",
            "operator:local",
            "--controller-id",
            "controller:local",
            "--controller-generation",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], BOOTSTRAP_WORKFLOW_SCHEMA);
    assert_eq!(value["proposal"]["expected_generation"], 0);
    assert_eq!(value["authorizes_mutation"], false);
    assert_eq!(value["activated"], false);

    let version = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        format!("iicp-management {}", env!("CARGO_PKG_VERSION"))
    );
}
