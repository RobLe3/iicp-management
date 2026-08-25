use iicp_client::runtime_health::{
    HealthSnapshot, Lifecycle, Liveness, ProgressSet, ProgressSnapshot, Readiness, ReasonCode,
    SubsystemState,
};
use iicp_management_core::runtime_observation::{
    parse_runtime_health, project_runtime_health, RuntimeEffectiveStateV1, RuntimeEvidenceStateV1,
    MAX_RUNTIME_HEALTH_BYTES, RUNTIME_OBSERVATION_SCHEMA,
};
use std::collections::BTreeMap;

fn snapshot() -> HealthSnapshot {
    HealthSnapshot {
        health_schema_version: 1,
        process_epoch: "private-process-epoch".into(),
        pid: 4242,
        sequence: 8,
        emitted_at: "2026-08-25T10:00:00Z".into(),
        lifecycle: Lifecycle::Running,
        liveness: Liveness::Live,
        readiness: Readiness::Ready,
        progress: ProgressSet {
            runtime: ProgressSnapshot {
                sequence: 8,
                age_ms: 0,
                stale_after_ms: 30_000,
                required: true,
            },
            supervisor: ProgressSnapshot {
                sequence: 8,
                age_ms: 0,
                stale_after_ms: 60_000,
                required: false,
            },
        },
        subsystems: BTreeMap::from([("provider".into(), SubsystemState::Healthy)]),
        external_connectivity: BTreeMap::from([("directory".into(), SubsystemState::Healthy)]),
        reason_codes: vec![],
    }
}

#[test]
fn current_snapshot_projects_without_process_identifiers_or_authority() {
    let output = project_runtime_health(&snapshot(), "node:local", 1_787_652_010).unwrap();
    assert_eq!(output.schema_version, RUNTIME_OBSERVATION_SCHEMA);
    assert_eq!(output.evidence_state, RuntimeEvidenceStateV1::Current);
    assert_eq!(output.effective_state, RuntimeEffectiveStateV1::Ready);
    assert!(!output.authorizes_mutation);
    let json = serde_json::to_value(output).unwrap();
    assert!(json.get("pid").is_none());
    assert!(json.get("process_epoch").is_none());
}

#[test]
fn stale_and_indeterminate_evidence_never_appears_ready() {
    let mut value = snapshot();
    value.reason_codes.push(ReasonCode::StateUnknown);
    let stale = project_runtime_health(&value, "node:local", 1_787_652_100).unwrap();
    assert_eq!(stale.evidence_state, RuntimeEvidenceStateV1::Stale);
    assert_eq!(stale.effective_state, RuntimeEffectiveStateV1::Unknown);
    assert!(stale
        .reason_codes
        .contains(&"IICP-MGMT-RUNTIME-EVIDENCE-STALE".into()));

    value.emitted_at = "2026-08-25T10:01:00Z".into();
    value.liveness = Liveness::Indeterminate;
    let unknown = project_runtime_health(&value, "node:local", 1_787_652_070).unwrap();
    assert_eq!(unknown.effective_state, RuntimeEffectiveStateV1::Unknown);
}

#[test]
fn malformed_future_sensitive_and_oversized_inputs_fail_closed() {
    let mut value = serde_json::to_value(snapshot()).unwrap();
    value["health_schema_version"] = 2.into();
    let parsed = parse_runtime_health(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        project_runtime_health(&parsed, "node:x", 1_787_652_010).unwrap_err(),
        "RUNTIME_HEALTH_SCHEMA_UNSUPPORTED"
    );

    value = serde_json::to_value(snapshot()).unwrap();
    value["emitted_at"] = "2026-08-25T10:01:00Z".into();
    let parsed = parse_runtime_health(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        project_runtime_health(&parsed, "node:x", 1_787_652_010).unwrap_err(),
        "RUNTIME_HEALTH_TIMESTAMP_FUTURE"
    );

    value = serde_json::to_value(snapshot()).unwrap();
    value["operator_secret"] = "never".into();
    assert_eq!(
        parse_runtime_health(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        "RUNTIME_HEALTH_SENSITIVE_FIELD_FORBIDDEN"
    );
    assert_eq!(
        parse_runtime_health(&vec![b' '; MAX_RUNTIME_HEALTH_BYTES + 1]).unwrap_err(),
        "RUNTIME_HEALTH_INPUT_TOO_LARGE"
    );
}

#[test]
fn output_validates_against_published_schema() {
    let output = serde_json::to_value(
        project_runtime_health(&snapshot(), "node:local", 1_787_652_010).unwrap(),
    )
    .unwrap();
    let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../contracts/runtime-observation-v1.schema.json"
    ))
    .unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&output)
        .unwrap();
}
