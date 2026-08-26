use iicp_client::runtime_health::{Liveness, Readiness, SubsystemState};
use iicp_management_core::adapters::{AdapterInspectionEntryV1, AdapterInspectionV1};
use iicp_management_core::bootstrap::*;
use iicp_management_core::controller::{ControllerSnapshot, DecisionRecord, DecisionState};
use iicp_management_core::diagnostics::*;
use iicp_management_core::profile::{
    controller_profile, ManagementProfileRequirementV1, MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA,
};
use iicp_management_core::rollout::{
    ConvergenceStatusV1, RunState, TargetRunState, TargetRunStatusV1, ROLLOUT_SCHEMA,
};
use iicp_management_core::runtime_observation::{
    RuntimeEffectiveStateV1, RuntimeEvidenceStateV1, RuntimeObservationV1, RUNTIME_HEALTH_SOURCE,
    RUNTIME_OBSERVATION_SCHEMA,
};
use iicp_management_core::{ConvergenceState, ExtensionClass, ExtensionRequirement};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn assessment() -> BootstrapAssessmentV1 {
    BootstrapAssessmentV1 {
        schema_version: BOOTSTRAP_SCHEMA.into(),
        assessment_id: "assessment:diagnostic".into(),
        environment_mode: EnvironmentMode::LocalOnly,
        observed_at: 100,
        expires_at: 200,
        readiness: AssessmentReadiness::ReadyForProposal,
        authorizes_mutation: false,
        observations: vec![],
        recommendations: vec![],
        required_decisions: vec![],
    }
}

fn controller() -> ControllerSnapshot {
    ControllerSnapshot {
        schema_version: "1".into(),
        evidence_class: "local_controller_snapshot".into(),
        authorizes_mutation: false,
        generation: 4,
        recent_decisions: vec![DecisionRecord {
            request_id: "private-request-id".into(),
            decision: DecisionState::Rejected,
            reason: "private-reason".into(),
            generation: 4,
            recorded_at: 110,
        }],
        adapter_capabilities: vec!["private-capability".into()],
        target_state: "converged".into(),
        accepted_state: "generation:4".into(),
        observed_state: "converged".into(),
        effective_state: "converged".into(),
        adapter_inspection: None,
    }
}

fn adapter() -> AdapterInspectionV1 {
    AdapterInspectionV1 {
        schema_version: "1".into(),
        evidence_class: "adapter_host_observation".into(),
        evidence_source: "domain_local_adapter_host".into(),
        authorizes_mutation: false,
        observed_at: 110,
        expires_at: 190,
        entries: vec![AdapterInspectionEntryV1 {
            target_id: "private-target".into(),
            registered_capability: "runtime-config-v1".into(),
            advertised_capabilities: vec!["runtime-config-v1".into()],
            descriptor_digest: format!("sha256:{}", "a".repeat(64)),
            observation_digest: Some(format!("sha256:{}", "b".repeat(64))),
            observed_generation: Some(4),
            convergence_state: Some(ConvergenceState::Converged),
            reason_code: "ADAPTER_OBSERVATION_VALID".into(),
        }],
        extensions: vec![],
    }
}

fn rollout() -> ConvergenceStatusV1 {
    ConvergenceStatusV1 {
        schema_version: ROLLOUT_SCHEMA.into(),
        run_id: "private-run".into(),
        manifest_digest: format!("sha256:{}", "c".repeat(64)),
        version: 2,
        state: RunState::Converged,
        current_batch: 1,
        partial_accepted: false,
        authorizes_target_execution: false,
        targets: vec![TargetRunStatusV1 {
            target_id: "private-target".into(),
            executor_ref: "private-executor".into(),
            batch: 0,
            required: true,
            state: TargetRunState::Converged,
            reason: "private-reason".into(),
            receipt: None,
        }],
    }
}

fn requirement() -> ManagementProfileRequirementV1 {
    ManagementProfileRequirementV1 {
        schema_version: MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA.into(),
        controller_id: Some("controller:test".into()),
        administrative_domain: Some("domain:test".into()),
        api_versions: vec![],
        schema_ids: vec![],
        canonicalization: vec![],
        signature_algorithms: vec![],
        operations: vec![],
        resource_kinds: vec![],
        policy_evaluators: vec![],
        extensions: vec![],
    }
}

fn runtime(state: RuntimeEffectiveStateV1) -> RuntimeObservationV1 {
    RuntimeObservationV1 {
        schema_version: RUNTIME_OBSERVATION_SCHEMA.into(),
        target_id: "private-runtime-target".into(),
        evidence_source: RUNTIME_HEALTH_SOURCE.into(),
        source_digest: format!("sha256:{}", "d".repeat(64)),
        observed_at: "1970-01-01T00:01:40.000Z".into(),
        expires_at: "1970-01-01T00:03:20.000Z".into(),
        evidence_state: RuntimeEvidenceStateV1::Current,
        reported_lifecycle: "running".into(),
        reported_liveness: if state == RuntimeEffectiveStateV1::Unknown {
            Liveness::Indeterminate
        } else {
            Liveness::Live
        },
        reported_readiness: match state {
            RuntimeEffectiveStateV1::Ready => Readiness::Ready,
            RuntimeEffectiveStateV1::Degraded => Readiness::Degraded,
            _ => Readiness::NotReady,
        },
        effective_state: state,
        reason_codes: vec![],
        subsystems: BTreeMap::from([("provider".into(), SubsystemState::Healthy)]),
        external_connectivity: BTreeMap::from([("directory".into(), SubsystemState::Healthy)]),
        authorizes_mutation: false,
    }
}

#[test]
fn runtime_aware_bundle_is_v2_minimized_and_schema_valid() {
    let value = create_diagnostic_bundle_v2(
        &assessment(),
        None,
        None,
        None,
        None,
        None,
        &runtime(RuntimeEffectiveStateV1::Ready),
        150,
    )
    .unwrap();
    assert_eq!(value.base.schema_version, DIAGNOSTIC_SCHEMA_V2);
    assert_eq!(value.base.artifacts.len(), 6);
    assert_eq!(
        value.base.checks.last().unwrap().reason_code,
        "RUNTIME_READY"
    );
    assert!(value
        .base
        .safe_next_actions
        .iter()
        .all(|v| v != "REVIEW_RUNTIME_EVIDENCE"));
    let serialized = serde_json::to_string(&value).unwrap();
    assert!(!serialized.contains("private-runtime-target"));
    assert!(!serialized.contains("process_epoch"));
    assert!(!serialized.contains("pid"));
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/diagnostic-bundle-v2.schema.json"
    ))
    .unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&serde_json::to_value(&value).unwrap())
        .unwrap();
    validate_diagnostic_bundle_v2(&value, 150).unwrap();
}

#[test]
fn runtime_diagnostic_projection_is_target_independent() {
    let mut first_runtime = runtime(RuntimeEffectiveStateV1::Ready);
    let mut second_runtime = first_runtime.clone();
    first_runtime.target_id = "node:first-private-target".into();
    second_runtime.target_id = "node:second-private-target".into();

    let first = create_diagnostic_bundle_v2(
        &assessment(),
        None,
        None,
        None,
        None,
        None,
        &first_runtime,
        150,
    )
    .unwrap();
    let second = create_diagnostic_bundle_v2(
        &assessment(),
        None,
        None,
        None,
        None,
        None,
        &second_runtime,
        150,
    )
    .unwrap();

    assert_eq!(first.runtime, second.runtime);
    assert_eq!(first.base.artifacts.last(), second.base.artifacts.last());
    for private in ["node:first-private-target", "node:second-private-target"] {
        assert!(!serde_json::to_string(&first).unwrap().contains(private));
        assert!(!serde_json::to_string(&second).unwrap().contains(private));
    }
}

#[test]
fn runtime_diagnostic_states_are_truthful_and_tamper_fails() {
    for (state, expected, check) in [
        (
            RuntimeEffectiveStateV1::Degraded,
            CheckState::Warn,
            "RUNTIME_DEGRADED",
        ),
        (
            RuntimeEffectiveStateV1::NotReady,
            CheckState::Fail,
            "RUNTIME_NOT_READY",
        ),
        (
            RuntimeEffectiveStateV1::Unknown,
            CheckState::Warn,
            "RUNTIME_STATE_UNKNOWN",
        ),
    ] {
        let value = create_diagnostic_bundle_v2(
            &assessment(),
            None,
            None,
            None,
            None,
            None,
            &runtime(state),
            150,
        )
        .unwrap();
        assert_eq!(value.base.overall, expected);
        assert_eq!(value.base.checks.last().unwrap().reason_code, check);
    }
    let mut stale = runtime(RuntimeEffectiveStateV1::Unknown);
    stale.evidence_state = RuntimeEvidenceStateV1::Stale;
    stale
        .reason_codes
        .push("IICP-MGMT-RUNTIME-EVIDENCE-STALE".into());
    let mut value =
        create_diagnostic_bundle_v2(&assessment(), None, None, None, None, None, &stale, 150)
            .unwrap();
    assert_eq!(
        value.base.checks.last().unwrap().reason_code,
        "RUNTIME_EVIDENCE_STALE"
    );
    value.runtime.reported_readiness = "ready".into();
    assert!(validate_diagnostic_bundle_v2(&value, 150).is_err());
}

#[test]
fn diagnostic_bundle_is_deterministic_minimized_and_schema_valid() {
    let profile = controller_profile(
        "controller:test",
        "domain:test",
        BTreeSet::from(["observe".into()]),
        BTreeSet::from(["runtime-config-v1".into()]),
        100,
    );
    let first = create_diagnostic_bundle(
        &assessment(),
        Some(&controller()),
        Some(&adapter()),
        Some(&profile),
        Some(&requirement()),
        Some(&rollout()),
        150,
    )
    .unwrap();
    let second = create_diagnostic_bundle(
        &assessment(),
        Some(&controller()),
        Some(&adapter()),
        Some(&profile),
        Some(&requirement()),
        Some(&rollout()),
        150,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.overall, CheckState::Pass);
    assert!(!first.authorizes_mutation);
    let serialized = serde_json::to_string(&first).unwrap();
    for private in [
        "private-request-id",
        "private-reason",
        "private-target",
        "private-executor",
        "private-capability",
    ] {
        assert!(!serialized.contains(private));
    }
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/diagnostic-bundle-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&serde_json::to_value(&first).unwrap()));
}

#[test]
fn missing_sources_remain_visible_and_tampering_fails() {
    let mut value =
        create_diagnostic_bundle(&assessment(), None, None, None, None, None, 150).unwrap();
    assert_eq!(value.overall, CheckState::Warn);
    assert_eq!(
        value
            .artifacts
            .iter()
            .filter(|item| item.state == DiagnosticArtifactState::NotAvailable)
            .count(),
        4
    );
    assert!(value
        .safe_next_actions
        .contains(&"PROVIDE_OR_REPAIR_CONTROLLER_EVIDENCE".into()));
    value.safe_next_actions.push("IGNORE_FAILURE".into());
    assert_eq!(
        validate_diagnostic_bundle(&value, 150).unwrap_err(),
        "DIAGNOSTIC_BUNDLE_INVALID"
    );
}

#[test]
fn invalid_stale_secret_and_required_extension_inputs_fail_closed() {
    assert!(
        create_diagnostic_bundle(&assessment(), None, Some(&adapter()), None, None, None, 201)
            .is_err()
    );
    let mut secret = assessment();
    secret.observations.push(EnvironmentObservationV1 {
        observation_id: "unsafe".into(),
        kind: "runtime".into(),
        source: "fixture".into(),
        status: ObservationStatus::Candidate,
        observed_at: 100,
        expires_at: 200,
        evidence_digest: None,
        details: json!({"prompt":"secret content"}),
    });
    secret.readiness = AssessmentReadiness::NeedsInput;
    assert!(create_diagnostic_bundle(&secret, None, None, None, None, None, 150).is_err());
    let mut private_state = controller();
    private_state.effective_state = "secret customer topology".into();
    assert_eq!(
        create_diagnostic_bundle(
            &assessment(),
            Some(&private_state),
            None,
            None,
            None,
            None,
            150
        )
        .unwrap_err(),
        "DIAGNOSTIC_CONTROLLER_INVALID"
    );
    let mut private_reason = adapter();
    private_reason.entries[0].reason_code = "customer secret".into();
    assert_eq!(
        create_diagnostic_bundle(
            &assessment(),
            None,
            Some(&private_reason),
            None,
            None,
            None,
            150
        )
        .unwrap_err(),
        "DIAGNOSTIC_ADAPTER_INVALID"
    );
    let mut unsupported = adapter();
    unsupported.extensions.push(ExtensionRequirement {
        id: "extension:future-security".into(),
        class: ExtensionClass::RequiredSecurityCritical,
    });
    assert_eq!(
        create_diagnostic_bundle(
            &assessment(),
            None,
            Some(&unsupported),
            None,
            None,
            None,
            150
        )
        .unwrap_err(),
        "DIAGNOSTIC_ADAPTER_INVALID"
    );
}

#[test]
fn partial_rollout_is_failed_with_actionable_summary() {
    let mut status = rollout();
    status.state = RunState::PartiallyConverged;
    status.targets[0].state = TargetRunState::Failed;
    let value = create_diagnostic_bundle(&assessment(), None, None, None, None, Some(&status), 150)
        .unwrap();
    assert_eq!(value.overall, CheckState::Fail);
    assert!(value
        .safe_next_actions
        .contains(&"REVIEW_ROLLOUT_CONVERGENCE".into()));
    assert_eq!(
        value.rollout.unwrap().target_counts,
        BTreeMap::from([("failed".into(), 1)])
    );
}

#[test]
fn conformance_fixture_ids_and_expected_outcomes_match_implementation() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/diagnostic-bundle-conformance-v1.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    let mut observed = BTreeMap::new();
    let profile = controller_profile(
        "controller:test",
        "domain:test",
        BTreeSet::from(["observe".into()]),
        BTreeSet::from(["runtime-config-v1".into()]),
        100,
    );
    let valid = create_diagnostic_bundle(
        &assessment(),
        Some(&controller()),
        Some(&adapter()),
        Some(&profile),
        Some(&requirement()),
        Some(&rollout()),
        150,
    )
    .unwrap();
    observed.insert(
        "all_sources_valid",
        (
            "accept",
            format!("{:?}", valid.overall).to_ascii_uppercase(),
        ),
    );
    let missing =
        create_diagnostic_bundle(&assessment(), None, None, None, None, None, 150).unwrap();
    observed.insert(
        "optional_sources_missing",
        (
            "accept",
            format!("{:?}", missing.overall).to_ascii_uppercase(),
        ),
    );
    let mut partial = rollout();
    partial.state = RunState::PartiallyConverged;
    let partial =
        create_diagnostic_bundle(&assessment(), None, None, None, None, Some(&partial), 150)
            .unwrap();
    observed.insert(
        "partial_rollout",
        (
            "accept",
            format!("{:?}", partial.overall).to_ascii_uppercase(),
        ),
    );
    for case in cases.iter().take(3) {
        let scenario = case["scenario"].as_str().unwrap();
        let actual = observed.get(scenario).unwrap();
        assert_eq!(actual.0, case["expected"]["result"]);
        assert_eq!(actual.1, case["expected"]["overall"]);
    }
    assert_eq!(
        cases[3]["expected"]["reason"],
        validate_diagnostic_bundle(
            &{
                let mut changed = valid.clone();
                changed.payload_digest = format!("sha256:{}", "0".repeat(64));
                changed
            },
            150
        )
        .unwrap_err()
    );
    let mut sensitive = assessment();
    sensitive.observations.push(EnvironmentObservationV1 {
        observation_id: "unsafe".into(),
        kind: "runtime".into(),
        source: "fixture".into(),
        status: ObservationStatus::Candidate,
        observed_at: 100,
        expires_at: 200,
        evidence_digest: None,
        details: json!({"api_key":"secret"}),
    });
    sensitive.readiness = AssessmentReadiness::NeedsInput;
    assert_eq!(
        cases[4]["expected"]["reason"],
        create_diagnostic_bundle(&sensitive, None, None, None, None, None, 150).unwrap_err()
    );
    let mut unsupported = adapter();
    unsupported.extensions.push(ExtensionRequirement {
        id: "extension:future-security".into(),
        class: ExtensionClass::RequiredSecurityCritical,
    });
    assert_eq!(
        cases[5]["expected"]["reason"],
        create_diagnostic_bundle(
            &assessment(),
            None,
            Some(&unsupported),
            None,
            None,
            None,
            150
        )
        .unwrap_err()
    );
}

#[test]
fn diagnostic_v2_fixture_states_match_implementation() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/diagnostic-bundle-conformance-v2.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for (scenario, state) in [
        ("runtime_ready", RuntimeEffectiveStateV1::Ready),
        ("runtime_degraded", RuntimeEffectiveStateV1::Degraded),
        ("runtime_not_ready", RuntimeEffectiveStateV1::NotReady),
        ("runtime_unknown", RuntimeEffectiveStateV1::Unknown),
    ] {
        let case = cases
            .iter()
            .find(|case| case["scenario"] == scenario)
            .unwrap();
        let bundle = create_diagnostic_bundle_v2(
            &assessment(),
            None,
            None,
            None,
            None,
            None,
            &runtime(state),
            150,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&bundle.runtime.effective_state).unwrap(),
            case["expected"]["effective_state"]
        );
        assert_eq!(
            format!("{:?}", bundle.base.checks.last().unwrap().state).to_ascii_uppercase(),
            case["expected"]["check_state"]
        );
        assert_eq!(
            bundle.base.checks.last().unwrap().reason_code,
            case["expected"]["reason"]
        );
    }
}
