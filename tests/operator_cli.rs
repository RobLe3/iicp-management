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
fn application_policy_and_dynamic_routing_are_inspectable() {
    let application = cli()
        .args([
            "--json",
            "show",
            "application",
            "application:finance",
            "policy",
            "brief",
            "--binding",
            "binding:finance",
            "--workspace",
            &example("proposed-workspace.json"),
            "--facts",
            &example("facts-us.json"),
        ])
        .output()
        .unwrap();
    assert!(
        application.status.success(),
        "{}",
        String::from_utf8_lossy(&application.stderr)
    );
    let value: Value = serde_json::from_slice(&application.stdout).unwrap();
    assert_eq!(value["application_id"], "application:finance");
    assert_eq!(value["binding_id"], "binding:finance");
    assert_eq!(value["effective_policy"]["decision"], "deny");
    assert!(value["effective_policy"]["fact_snapshot_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    let routing = cli()
        .args([
            "show",
            "routing",
            "urn:iicp:intent:finance:invoice-analysis:v1",
            "--binding",
            "binding:finance",
            "--workspace",
            &example("proposed-workspace.json"),
            "--facts",
            &example("facts-us.json"),
            "--brief",
            "--preference",
            "local-eu",
        ])
        .output()
        .unwrap();
    assert!(routing.status.success());
    let summary = String::from_utf8_lossy(&routing.stdout);
    assert!(summary.contains("dynamic evidence-bound resolution"));
    assert!(!summary.contains("provider"));
    assert!(!summary.contains("next hop"));
}

#[test]
fn inspection_rejects_application_mismatch_and_preserves_indeterminate() {
    let mismatch = cli()
        .args([
            "show",
            "application",
            "application:other",
            "policy",
            "brief",
            "--binding",
            "binding:finance",
            "--workspace",
            &example("proposed-workspace.json"),
            "--facts",
            &example("facts-us.json"),
        ])
        .output()
        .unwrap();
    assert_eq!(mismatch.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("APPLICATION_BINDING_MISMATCH"));

    let directory = tempfile::tempdir().unwrap();
    let facts = directory.path().join("facts.json");
    fs::write(&facts, b"{}\n").unwrap();
    let routing = cli()
        .args([
            "--json",
            "show",
            "routing",
            "urn:iicp:intent:finance:invoice-analysis:v1",
            "--binding",
            "binding:finance",
            "--workspace",
            &example("proposed-workspace.json"),
            "--facts",
            facts.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(routing.status.success());
    let value: Value = serde_json::from_slice(&routing.stdout).unwrap();
    assert_eq!(value["eligible"], false);
    assert_eq!(value["decision"], "indeterminate");
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

#[test]
fn diagnostic_cli_creates_verifies_and_explains_a_private_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let assessment = directory.path().join("assessment.json");
    let bundle = directory.path().join("diagnostic.json");
    let now = Controller::now();
    fs::write(
        &assessment,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":"iicp.management-bootstrap-assessment.v1",
            "assessment_id":"assessment:diagnostic-cli",
            "environment_mode":"local_only",
            "observed_at":now,
            "expires_at":now+300,
            "readiness":"ready_for_proposal",
            "authorizes_mutation":false,
            "observations":[],
            "recommendations":[],
            "required_decisions":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let create = cli()
        .args([
            "--json",
            "diagnostics",
            "create",
            assessment.to_str().unwrap(),
            "--profile",
            &example("management-profile.json"),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let value: Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(value["authorizes_mutation"], false);
    assert_eq!(value["overall"], "WARN");
    let bytes = fs::read(&bundle).unwrap();
    for forbidden in ["prompt", "response", "credential", "private_key", "api_key"] {
        assert!(!String::from_utf8_lossy(&bytes).contains(forbidden));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let verify = cli()
        .args(["diagnostics", "verify", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verify.status.success());
    let show = cli()
        .args(["diagnostics", "show", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(show.status.success());
    let summary = String::from_utf8_lossy(&show.stdout);
    assert!(summary.contains("Overall: Warn"));
    assert!(summary.contains("PROVIDE_OR_REPAIR_CONTROLLER_EVIDENCE"));

    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["overall"] = serde_json::json!("PASS");
    fs::write(&bundle, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let rejected = cli()
        .args(["diagnostics", "verify", bundle.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("DIAGNOSTIC_BUNDLE_INVALID"));
}

#[test]
fn diagnostic_collection_opens_controller_database_read_only() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let assessment = directory.path().join("assessment.json");
    let bundle = directory.path().join("diagnostic.json");
    let key = SigningKey::from_bytes(&[31; 32]);
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
    let now = Controller::now();
    fs::write(
        &assessment,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":"iicp.management-bootstrap-assessment.v1",
            "assessment_id":"assessment:read-only",
            "environment_mode":"local_only",
            "observed_at":now,
            "expires_at":now+300,
            "readiness":"ready_for_proposal",
            "authorizes_mutation":false,
            "observations":[],"recommendations":[],"required_decisions":[]
        }))
        .unwrap(),
    )
    .unwrap();
    let before = fs::read(&database).unwrap();
    let output = cli()
        .args([
            "diagnostics",
            "create",
            assessment.to_str().unwrap(),
            "--controller",
            database.to_str().unwrap(),
            "--output",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(before, fs::read(&database).unwrap());
}
