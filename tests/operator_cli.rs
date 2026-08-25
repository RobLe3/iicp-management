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
fn profile_cli_verifies_and_intersects_the_finance_example() {
    let verify = cli()
        .args([
            "--json",
            "profile",
            "verify",
            &example("management-profile.json"),
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let value: Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["authorizes_mutation"], false);

    let intersection = cli()
        .args([
            "--json",
            "profile",
            "intersect",
            &example("management-profile.json"),
            &example("management-profile-requirement.json"),
        ])
        .output()
        .unwrap();
    assert!(intersection.status.success());
    let value: Value = serde_json::from_slice(&intersection.stdout).unwrap();
    assert_eq!(value["compatibility"], "compatible");
    assert_eq!(value["authorizes_mutation"], false);
}

#[test]
fn doctor_reports_profile_compatibility_without_authority() {
    let directory = tempfile::tempdir().unwrap();
    let assessment = directory.path().join("assessment.json");
    let invalid_adapter = directory.path().join("adapter.json");
    let missing_controller = directory.path().join("missing.db");
    let now = Controller::now();
    fs::write(
        &assessment,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":"iicp.management-bootstrap-assessment.v1",
            "assessment_id":"assessment:profile-doctor",
            "environment_mode":"local_only",
            "observed_at":now,
            "expires_at":now+60,
            "readiness":"ready_for_proposal",
            "authorizes_mutation":false,
            "observations":[],
            "recommendations":[],
            "required_decisions":[]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(&invalid_adapter, b"{}").unwrap();
    let output = cli()
        .args([
            "--json",
            "doctor",
            assessment.to_str().unwrap(),
            missing_controller.to_str().unwrap(),
            invalid_adapter.to_str().unwrap(),
            &example("management-profile.json"),
            &example("management-profile-requirement.json"),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let check = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["check_id"] == "management_profile")
        .unwrap();
    assert_eq!(check["state"], "PASS");
    assert_eq!(value["authorizes_mutation"], false);
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

    let now = Controller::now();
    let adapter = directory.path().join("adapter.json");
    fs::write(
        &adapter,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":"1",
            "evidence_class":"adapter_host_observation",
            "evidence_source":"domain_local_adapter_host",
            "authorizes_mutation":false,
            "observed_at":now,
            "expires_at":now+60,
            "entries":[{
                "target_id":"target:test",
                "registered_capability":"synthetic-v1",
                "advertised_capabilities":["synthetic-v1"],
                "descriptor_digest":format!("sha256:{}", "a".repeat(64)),
                "observation_digest":format!("sha256:{}", "b".repeat(64)),
                "observed_generation":0,
                "convergence_state":"converged",
                "reason_code":"ADAPTER_RECEIPT_REPORTED"
            }],
            "extensions":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let combined = cli()
        .args([
            "--json",
            "controller",
            "status",
            database.to_str().unwrap(),
            adapter.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(combined.status.success());
    let value: Value = serde_json::from_slice(&combined.stdout).unwrap();
    assert_eq!(value["observed_state"], "converged");
    assert_eq!(value["effective_state"], "converged");
    assert_eq!(value["adapter_capabilities"][0], "synthetic-v1");
    assert_eq!(before, fs::read(&database).unwrap());

    let mut mismatched: Value = serde_json::from_slice(&fs::read(&adapter).unwrap()).unwrap();
    mismatched["entries"][0]["observed_generation"] = Value::from(1);
    fs::write(&adapter, serde_json::to_vec_pretty(&mismatched).unwrap()).unwrap();
    let combined = cli()
        .args([
            "--json",
            "controller",
            "status",
            database.to_str().unwrap(),
            adapter.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(combined.status.success());
    let value: Value = serde_json::from_slice(&combined.stdout).unwrap();
    assert_eq!(value["effective_state"], "generation_mismatch");
    assert_eq!(before, fs::read(&database).unwrap());
}
