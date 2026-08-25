use iicp_management_core::bootstrap::*;
use iicp_management_core::ManagedResource;
use serde_json::json;

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
