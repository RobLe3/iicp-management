use serde_json::Value;
use std::fs;
use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_iicp-management-conformance"))
}

fn temporary_fixture(name: &str, content: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "iicp-management-{name}-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(&path, content).unwrap();
    path
}

#[test]
fn built_in_conformance_pack_passes_with_json_report() {
    let output = binary().output().unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 26);
    assert_eq!(report["failed"], 0);
    assert_eq!(report["evidence_class"], "project-verified");
}

#[test]
fn mismatch_returns_exit_one_and_malformed_input_returns_exit_two() {
    let original = include_str!("../fixtures/policy-evaluator-cases-v0.json");
    let mut fixture: Value = serde_json::from_str(original).unwrap();
    fixture["cases"][0]["expected"]["decision"] = Value::String("deny".into());
    let mismatch = temporary_fixture("mismatch", &serde_json::to_string(&fixture).unwrap());
    let mismatch_output = binary().arg(&mismatch).output().unwrap();
    assert_eq!(mismatch_output.status.code(), Some(1));

    let malformed = temporary_fixture("malformed", "not-json");
    let malformed_output = binary().arg(&malformed).output().unwrap();
    assert_eq!(malformed_output.status.code(), Some(2));

    fs::remove_file(mismatch).unwrap();
    fs::remove_file(malformed).unwrap();
}
