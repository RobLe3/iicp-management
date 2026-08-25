use iicp_management_core::trial::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn participant() -> ParticipantQualificationV2 {
    ParticipantQualificationV2 {
        role: AdministratorRole::InfrastructureAdministrator,
        prior_iicp_exposure: PriorIicpExposure::None,
        contributed_to_tested_workflow: false,
        consent_recorded: true,
    }
}

fn environment() -> TrialEnvironmentV2 {
    TrialEnvironmentV2 {
        tested_build: "iicp-management/0.4.0-rc.1".into(),
        platform: TrialPlatform::Linux,
        deployment_shape: DeploymentShape::DisposableLocal,
        enabled_management_profiles: vec![],
    }
}

#[test]
fn schemas_accept_every_serialized_contract_and_reject_personal_fields() {
    let schema: Value = serde_json::from_str(include_str!(
        "../contracts/administrator-trial-v2.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let definition = TrialDefinitionV2 {
        schema_version: TRIAL_DEFINITION_SCHEMA.into(),
        trial_id: "trial:schema".into(),
        evidence_class: EvidenceClassV2::RepresentativeObservation,
        workflow: TrialWorkflow::DiagnoseFailedResolution,
        participant: participant(),
        environment: environment(),
        authorizes_mutation: false,
    };
    let event = TrialEventV2 {
        schema_version: TRIAL_EVENT_SCHEMA.into(),
        event_id: "event:schema".into(),
        occurred_at: 10,
        kind: TrialEventKind::Interaction,
        phase_code: "diagnosis".into(),
    };
    let session = TrialSessionV2 {
        schema_version: TRIAL_SESSION_SCHEMA.into(),
        definition: definition.clone(),
        started_at: 10,
        events: vec![event.clone()],
        finalized: false,
        authorizes_mutation: false,
    };
    let outcome = TrialOutcomeV2 {
        schema_version: TRIAL_OUTCOME_SCHEMA.into(),
        completed_at: 20,
        outcome: TrialOutcomeKind::Success,
        machine_result_digest: Some(format!("sha256:{}", "a".repeat(64))),
        canonical_test_references: vec!["test:diagnosis:receipt".into()],
    };
    let evidence = finish_trial(&session, outcome.clone()).unwrap();
    let summary = TrialSummaryV2 {
        schema_version: TRIAL_SUMMARY_SCHEMA.into(),
        workflow: TrialWorkflow::DiagnoseFailedResolution,
        total_observations: 1,
        successful: 1,
        failed: 0,
        abandoned: 0,
        assisted: 0,
        completion_rate_basis_points: 10_000,
        duration_min_seconds: 10,
        duration_median_seconds: 10,
        duration_max_seconds: 10,
        representative_observations: 1,
        representative_role_count: 1,
        evidence_class_counts: BTreeMap::from([("representative_observation".into(), 1)]),
        numerical_threshold_met: false,
        authorizes_mutation: false,
        release_gate_authorized: false,
    };
    for value in [
        serde_json::to_value(definition).unwrap(),
        serde_json::to_value(event).unwrap(),
        serde_json::to_value(session).unwrap(),
        serde_json::to_value(outcome).unwrap(),
        serde_json::to_value(evidence).unwrap(),
        serde_json::to_value(summary).unwrap(),
    ] {
        assert!(validator.is_valid(&value), "schema rejected {value}");
    }
    let mut unsafe_definition: Value = serde_json::from_str(include_str!(
        "../examples/trials/policy-simulation-definition.json"
    ))
    .unwrap();
    unsafe_definition["participant"]["name"] = json!("forbidden");
    assert!(!validator.is_valid(&unsafe_definition));
}

#[test]
fn fixture_covers_the_required_bounded_cases() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/administrator-trial-conformance-v2.json"
    ))
    .unwrap();
    let ids = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 8);
    assert!(ids.contains("TRIAL-01"));
    assert!(ids.contains("TRIAL-08"));
    assert_eq!(fixture["non_claims"].as_array().unwrap().len(), 4);
}
