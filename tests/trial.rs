use iicp_management_core::trial::*;

fn definition(id: &str, role: AdministratorRole) -> TrialDefinitionV2 {
    TrialDefinitionV2 {
        schema_version: TRIAL_DEFINITION_SCHEMA.into(),
        trial_id: id.into(),
        evidence_class: EvidenceClassV2::RepresentativeObservation,
        workflow: TrialWorkflow::CreateAndSimulateSimplePolicy,
        participant: ParticipantQualificationV2 {
            role,
            prior_iicp_exposure: PriorIicpExposure::None,
            contributed_to_tested_workflow: false,
            consent_recorded: true,
        },
        environment: TrialEnvironmentV2 {
            tested_build: "iicp-management/0.4.0-rc.1".into(),
            platform: TrialPlatform::Linux,
            deployment_shape: DeploymentShape::DisposableLocal,
            enabled_management_profiles: vec!["management-local-ipc/v1".into()],
        },
        authorizes_mutation: false,
    }
}

fn completed_evidence(
    id: &str,
    role: AdministratorRole,
    outcome: TrialOutcomeKind,
) -> FrictionEvidenceV2 {
    let mut session = start_trial(definition(id, role), 100).unwrap();
    record_event(
        &mut session,
        TrialEventV2 {
            schema_version: TRIAL_EVENT_SCHEMA.into(),
            event_id: format!("event:{id}:1"),
            occurred_at: 105,
            kind: TrialEventKind::Interaction,
            phase_code: "policy_preview".into(),
        },
    )
    .unwrap();
    finish_trial(
        &session,
        TrialOutcomeV2 {
            schema_version: TRIAL_OUTCOME_SCHEMA.into(),
            completed_at: 120,
            outcome,
            machine_result_digest: Some(format!("sha256:{}", "a".repeat(64))),
            canonical_test_references: vec![format!("test:{id}:receipt")],
        },
    )
    .unwrap()
}

#[test]
fn representative_trial_records_bounded_evidence_without_authority() {
    let evidence = completed_evidence(
        "trial:representative:1",
        AdministratorRole::InfrastructureAdministrator,
        TrialOutcomeKind::Success,
    );
    assert_eq!(evidence.claim_status, "observer_declared");
    assert_eq!(evidence.interaction_count, 1);
    assert_eq!(evidence.duration_seconds, 20);
    assert!(evidence.unassisted_success);
    assert!(!evidence.authorizes_mutation);
    assert!(!evidence.release_gate_authorized);
    validate_evidence(&evidence).unwrap();
}

#[test]
fn contributor_cannot_be_classified_as_representative_or_independent() {
    let mut value = definition("trial:invalid", AdministratorRole::Developer);
    value.participant.prior_iicp_exposure = PriorIicpExposure::Contributor;
    value.participant.contributed_to_tested_workflow = true;
    assert_eq!(
        validate_definition(&value).unwrap_err(),
        "TRIAL_QUALIFICATION_INVALID"
    );
    value.evidence_class = EvidenceClassV2::IndependentReproduction;
    assert_eq!(
        validate_definition(&value).unwrap_err(),
        "TRIAL_QUALIFICATION_INVALID"
    );
}

#[test]
fn duplicate_out_of_order_and_post_finalization_events_fail() {
    let mut session = start_trial(
        definition("trial:events", AdministratorRole::SystemAdministrator),
        100,
    )
    .unwrap();
    let event = TrialEventV2 {
        schema_version: TRIAL_EVENT_SCHEMA.into(),
        event_id: "event:1".into(),
        occurred_at: 110,
        kind: TrialEventKind::Interaction,
        phase_code: "start".into(),
    };
    record_event(&mut session, event.clone()).unwrap();
    assert_eq!(
        record_event(&mut session, event).unwrap_err(),
        "TRIAL_EVENT_INVALID"
    );
    assert_eq!(session.events.len(), 1);

    let stale = TrialEventV2 {
        schema_version: TRIAL_EVENT_SCHEMA.into(),
        event_id: "event:2".into(),
        occurred_at: 109,
        kind: TrialEventKind::ExplicitInput,
        phase_code: "input".into(),
    };
    assert_eq!(
        record_event(&mut session, stale).unwrap_err(),
        "TRIAL_EVENT_INVALID"
    );
    session.finalized = true;
    let next = TrialEventV2 {
        schema_version: TRIAL_EVENT_SCHEMA.into(),
        event_id: "event:3".into(),
        occurred_at: 111,
        kind: TrialEventKind::Interaction,
        phase_code: "finish".into(),
    };
    assert_eq!(
        record_event(&mut session, next).unwrap_err(),
        "TRIAL_ALREADY_FINALIZED"
    );
}

#[test]
fn assisted_failed_and_abandoned_runs_are_retained_in_summary() {
    let roles = [
        AdministratorRole::InfrastructureAdministrator,
        AdministratorRole::SystemAdministrator,
        AdministratorRole::CloudEngineer,
        AdministratorRole::SecurityEngineer,
        AdministratorRole::SapAdministrator,
    ];
    let mut evidence = roles
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            completed_evidence(
                &format!("trial:summary:{index}"),
                role,
                if index == 3 {
                    TrialOutcomeKind::Failed
                } else if index == 4 {
                    TrialOutcomeKind::Abandoned
                } else {
                    TrialOutcomeKind::Success
                },
            )
        })
        .collect::<Vec<_>>();
    evidence[1].assistance_count = 1;
    evidence[1].unassisted_success = false;
    validate_evidence(&evidence[1]).unwrap();
    let summary = summarize_trials(&evidence).unwrap();
    assert_eq!(summary.total_observations, 5);
    assert_eq!(summary.successful, 3);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.abandoned, 1);
    assert_eq!(summary.assisted, 1);
    assert_eq!(summary.representative_role_count, 5);
    assert!(summary.numerical_threshold_met);
    assert!(!summary.authorizes_mutation);
    assert!(!summary.release_gate_authorized);
}

#[test]
fn fewer_observations_or_roles_do_not_meet_numerical_threshold() {
    let evidence = (0..5)
        .map(|index| {
            completed_evidence(
                &format!("trial:single-role:{index}"),
                AdministratorRole::SystemAdministrator,
                TrialOutcomeKind::Success,
            )
        })
        .collect::<Vec<_>>();
    assert!(!summarize_trials(&evidence).unwrap().numerical_threshold_met);
    assert_eq!(
        summarize_trials(&evidence[..4])
            .unwrap()
            .representative_observations,
        4
    );
}

#[test]
fn summaries_do_not_mix_workflow_budgets() {
    let first = completed_evidence(
        "trial:workflow:1",
        AdministratorRole::SystemAdministrator,
        TrialOutcomeKind::Success,
    );
    let mut second = completed_evidence(
        "trial:workflow:2",
        AdministratorRole::CloudEngineer,
        TrialOutcomeKind::Success,
    );
    second.workflow = TrialWorkflow::ConnectNewSite;
    assert_eq!(
        summarize_trials(&[first, second]).unwrap_err(),
        "TRIAL_SUMMARY_WORKFLOW_MIXED"
    );
}

#[test]
fn success_requires_machine_checkable_result_and_test_only_references() {
    let session = start_trial(
        definition("trial:outcome", AdministratorRole::CloudEngineer),
        100,
    )
    .unwrap();
    let missing = TrialOutcomeV2 {
        schema_version: TRIAL_OUTCOME_SCHEMA.into(),
        completed_at: 110,
        outcome: TrialOutcomeKind::Success,
        machine_result_digest: None,
        canonical_test_references: vec![],
    };
    assert_eq!(
        finish_trial(&session, missing).unwrap_err(),
        "TRIAL_OUTCOME_INVALID"
    );
    let unsafe_reference = TrialOutcomeV2 {
        schema_version: TRIAL_OUTCOME_SCHEMA.into(),
        completed_at: 110,
        outcome: TrialOutcomeKind::Failed,
        machine_result_digest: None,
        canonical_test_references: vec!["production:finance".into()],
    };
    assert_eq!(
        finish_trial(&session, unsafe_reference).unwrap_err(),
        "TRIAL_OUTCOME_INVALID"
    );
}

#[test]
fn unknown_or_personal_fields_fail_deserialization() {
    let mut value = serde_json::to_value(definition(
        "trial:privacy",
        AdministratorRole::SecurityEngineer,
    ))
    .unwrap();
    value["participant"]["name"] = serde_json::json!("Not permitted");
    assert!(serde_json::from_value::<TrialDefinitionV2>(value).is_err());
}
