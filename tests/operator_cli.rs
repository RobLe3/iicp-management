use ed25519_dalek::SigningKey;
use iicp_management_core::controller::{Controller, ControllerPolicy};
use serde_json::Value;
use std::{collections::BTreeSet, fs, process::Command};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_iicp-management"))
}

fn example(name: &str) -> String {
    format!("{}/examples/finance/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn finance_workflow_is_deterministic_and_explainable() {
    let plan = cli()
        .args([
            "--json",
            "plan",
            &example("desired-state.json"),
            &example("accepted-state.json"),
        ])
        .output()
        .unwrap();
    assert!(plan.status.success());
    let value: Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(value["operations"][0]["resource_id"], "binding:finance");

    let effective = cli()
        .args([
            "--json",
            "show",
            "effective-policy",
            &example("proposed-workspace.json"),
            &example("facts-us.json"),
            "binding:finance",
        ])
        .output()
        .unwrap();
    assert!(effective.status.success());
    let value: Value = serde_json::from_slice(&effective.stdout).unwrap();
    assert_eq!(value["decision"], "deny");
    assert!(value["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "IICP-POLICY-EFFECTIVE-DENY"));

    let simulation = cli()
        .args([
            "--json",
            "simulate",
            &example("current-workspace.json"),
            &example("proposed-workspace.json"),
            &example("facts-us.json"),
            "binding:finance",
        ])
        .output()
        .unwrap();
    assert!(simulation.status.success());
    let value: Value = serde_json::from_slice(&simulation.stdout).unwrap();
    assert_eq!(value["decision_changed"], true);
    assert_eq!(value["newly_denied"], true);
}

#[test]
fn required_unknown_and_changed_receipt_fail_closed() {
    let unknown = cli()
        .args(["validate", &example("unknown-required-extension.json")])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("PROFILE_UNSUPPORTED_REQUIRED"));

    let changed = cli()
        .args([
            "verify-receipt",
            &example("receipt-tampered.json"),
            &example("plan.json"),
            "domain:finance",
        ])
        .output()
        .unwrap();
    assert_eq!(changed.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&changed.stderr).contains("RECEIPT_BINDING_MISMATCH"));
}

#[test]
fn controller_inspection_is_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let key = SigningKey::from_bytes(&[29; 32]);
    let controller = Controller::open(
        &database,
        ControllerPolicy {
            audience: "controller:test".into(),
            domain: "domain:test".into(),
            allowed_actions: BTreeSet::from(["apply".into()]),
            revocation_checkpoint: Controller::now(),
            max_checkpoint_age: 3600,
            high_impact_actions: BTreeSet::new(),
            max_decision_events: 100,
        },
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    drop(controller);
    let before = fs::read(&database).unwrap();
    let output = cli()
        .args(["--json", "controller", "status", database.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["generation"], 0);
    assert_eq!(value["evidence_class"], "local_controller_snapshot");
    assert_eq!(value["authorizes_mutation"], false);
    assert_eq!(value["target_state"], "not_reported_by_controller_store");
    assert_eq!(before, fs::read(&database).unwrap());
}
