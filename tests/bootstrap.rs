use iicp_client::runtime_config::{OperatingMode, RuntimeConfigV1};
use iicp_management_core::bootstrap::*;
use iicp_management_core::runtime_observation::{parse_runtime_health, project_runtime_health};
use iicp_management_core::ManagedResource;
use serde_json::json;
use std::io::Write;
use std::process::{Command, Stdio};

fn assessment(mode: EnvironmentMode) -> BootstrapAssessmentV1 {
    BootstrapAssessmentV1 {
        schema_version: BOOTSTRAP_SCHEMA.into(),
        assessment_id: "assessment:test".into(),
        environment_mode: mode,
        observed_at: 100,
        expires_at: 200,
        readiness: AssessmentReadiness::ReadyForProposal,
        authorizes_mutation: false,
        observations: vec![EnvironmentObservationV1 {
            observation_id: "runtime:test".into(),
            kind: "runtime".into(),
            source: "fixture".into(),
            status: ObservationStatus::Verified,
            observed_at: 100,
            expires_at: 200,
            evidence_digest: Some(format!("sha256:{}", "a".repeat(64))),
            details: json!({"capability":"synthetic-v1"}),
        }],
        recommendations: vec![BootstrapRecommendationV1 {
            recommendation_id: "resource:test".into(),
            reason: "verified local runtime".into(),
            resource: Some(ManagedResource {
                resource_id: "runtime:test".into(),
                kind: "synthetic-v1".into(),
                desired: json!({"enabled":true}),
                secret_refs: Default::default(),
            }),
            requires_decision_ids: vec![],
        }],
        required_decisions: vec![],
    }
}

#[test]
fn verified_assessment_produces_non_activating_proposal_and_doctor_report() {
    let value = assessment(EnvironmentMode::LocalOnly);
    validate_assessment(&value, 150).unwrap();
    let proposal = create_proposal(&value, "operator:test", "controller:test", 0, 150).unwrap();
    assert_eq!(proposal.resources.len(), 1);
    assert!(!doctor(&value, 150, Some(true), Some(true)).authorizes_mutation);
    assert_eq!(
        doctor(&value, 150, Some(true), Some(true)).overall,
        CheckState::Pass
    );
    assert!(!validate_import(&proposal).unwrap().is_empty());
}

#[test]
fn stale_unknown_secret_and_public_fallback_evidence_fail_closed() {
    let mut value = assessment(EnvironmentMode::LocalOnly);
    assert!(validate_assessment(&value, 201).is_err());
    value.expires_at = 300;
    value.observations[0].expires_at = 300;
    value.observations[0].details = json!({"api_key":"forbidden"});
    assert!(validate_assessment(&value, 150).is_err());
    value.observations[0].details = json!({});
    value.recommendations[0].resource.as_mut().unwrap().desired =
        json!({"directory":"https://iicp.network/api"});
    assert_eq!(
        validate_assessment(&value, 150).unwrap_err(),
        "BOOTSTRAP_PUBLIC_FALLBACK_FORBIDDEN"
    );
    value.recommendations.clear();
    value.observations[0].status = ObservationStatus::Candidate;
    assert_eq!(
        validate_assessment(&value, 150).unwrap_err(),
        "BOOTSTRAP_READINESS_INVALID"
    );
}

#[test]
fn doctor_keeps_missing_optional_evidence_visible() {
    let report = doctor(&assessment(EnvironmentMode::Public), 150, None, None);
    assert_eq!(report.overall, CheckState::Warn);
    assert_eq!(
        report
            .checks
            .iter()
            .filter(|c| c.state == CheckState::NotAvailable)
            .count(),
        2
    );
}

#[test]
fn doctor_distinguishes_invalid_evidence_from_missing_evidence() {
    let report = doctor(
        &assessment(EnvironmentMode::Public),
        150,
        Some(false),
        Some(false),
    );
    assert_eq!(report.overall, CheckState::Fail);
    assert_eq!(
        report
            .checks
            .iter()
            .filter(|check| check.state == CheckState::Fail)
            .count(),
        2
    );
}

#[test]
fn assessment_contract_accepts_the_serialized_reference_fixture() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/bootstrap-assessment-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let instance = serde_json::to_value(assessment(EnvironmentMode::Public)).unwrap();
    assert!(validator.is_valid(&instance));
}

#[test]
fn disposable_sandbox_is_machine_readable_and_non_representative() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args(["bootstrap", "sandbox"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["activated"], false);
    assert_eq!(value["friction_evidence"]["representative"], false);
    assert_eq!(
        value["friction_evidence"]["evidence_class"],
        "project_rehearsal"
    );
    assert_eq!(value["friction_evidence"]["interaction_count"], 5);
    assert_eq!(value["rendered_template"]["authorizes_activation"], false);
    assert_eq!(value["impact"]["authorizes_mutation"], false);
    assert_eq!(value["simulation"]["newly_denied"], true);
    assert_eq!(value["plan"]["operations"].as_array().unwrap().len(), 1);
    assert_eq!(value["diagnostic_bundle"]["authorizes_mutation"], false);
    assert_eq!(value["diagnostic_bundle"]["overall"], "WARN");
}

#[test]
fn project_rehearsal_cannot_claim_representative_evidence() {
    let value = FrictionEvidenceV1 {
        schema_version: FRICTION_SCHEMA.into(),
        evidence_id: "e".into(),
        evidence_class: "project_rehearsal".into(),
        workflow: "w".into(),
        actor_class: "maintainer".into(),
        started_at: 1,
        completed_at: 2,
        interaction_count: 1,
        outcome: "complete".into(),
        representative: true,
        authorizes_mutation: false,
    };
    assert_eq!(
        validate_friction(&value).unwrap_err(),
        "FRICTION_REPRESENTATIVE_CLAIM_INVALID"
    );
}

#[test]
fn runtime_config_becomes_a_ready_non_authorizing_assessment() {
    let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let value = assessment_from_runtime_config(&config, "runtime:local", None, 100).unwrap();
    assert_eq!(value.environment_mode, EnvironmentMode::LocalOnly);
    assert_eq!(value.readiness, AssessmentReadiness::ReadyForProposal);
    assert!(!value.authorizes_mutation);
    assert_eq!(value.recommendations.len(), 1);
    assert_eq!(
        value.recommendations[0].resource.as_ref().unwrap().kind,
        "RuntimeConfigV1"
    );
    let proposal = create_proposal(&value, "operator:local", "controller:local", 0, 100).unwrap();
    assert_eq!(proposal.resources.len(), 1);
    assert_eq!(proposal.resources[0].desired["mode"], "local_only");
}

#[test]
fn runtime_config_preflight_rejects_invalid_config_and_target_mismatch() {
    let mut config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    config.schema_version = 99;
    assert_eq!(
        assessment_from_runtime_config(&config, "runtime:local", None, 100).unwrap_err(),
        "BOOTSTRAP_RUNTIME_CONFIG_INVALID"
    );

    let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let snapshot =
        parse_runtime_health(include_bytes!("../fixtures/runtime-health-ready-v1.json")).unwrap();
    let runtime = project_runtime_health(&snapshot, "runtime:other", 1_787_700_000).unwrap();
    assert_eq!(
        assessment_from_runtime_config(&config, "runtime:local", Some(&runtime), 1_787_700_000)
            .unwrap_err(),
        "BOOTSTRAP_RUNTIME_TARGET_MISMATCH"
    );
}

#[test]
fn runtime_config_preflight_cli_supports_file_and_bounded_stdin() {
    let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), serde_json::to_vec(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "bootstrap",
            "from-runtime-config",
            file.path().to_str().unwrap(),
            "--resource-id",
            "runtime:file",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["readiness"], "ready_for_proposal");
    assert_eq!(value["authorizes_mutation"], false);

    let mut child = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "bootstrap",
            "from-runtime-config",
            "-",
            "--resource-id",
            "runtime:stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&config).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["recommendations"][0]["resource"]["resource_id"],
        "runtime:stdin"
    );
}

#[test]
fn runtime_config_preflight_cli_binds_optional_runtime_evidence() {
    let config = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config_file.path(), serde_json::to_vec(&config).unwrap()).unwrap();
    let runtime_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        runtime_file.path(),
        include_bytes!("../fixtures/runtime-health-ready-v1.json"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "bootstrap",
            "from-runtime-config",
            config_file.path().to_str().unwrap(),
            "--resource-id",
            "runtime:local",
            "--runtime-health",
            runtime_file.path().to_str().unwrap(),
            "--runtime-target",
            "runtime:local",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["observations"].as_array().unwrap().len(), 2);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("fixture-process-epoch"));
    assert!(!text.contains("4242"));

    let partial = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "bootstrap",
            "from-runtime-config",
            config_file.path().to_str().unwrap(),
            "--resource-id",
            "runtime:local",
            "--runtime-health",
            runtime_file.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!partial.status.success());
}
