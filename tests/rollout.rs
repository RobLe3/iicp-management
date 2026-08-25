use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::{
    adapters::{AdapterInspectionEntryV1, AdapterInspectionV1, AdapterOperation, AdapterReceipt},
    apply_gate::{
        authorization_signing_bytes, ApplyAuthorizationEvidenceV1, LocalApplyGateV1,
        APPLY_GATE_SCHEMA,
    },
    controller::{ManagementRequest, SIGNATURE_PROFILE},
    digest,
    execution::{ApplyLifecycleReceiptV1, ExecutionState, RetryDisposition},
    progressive_authority::{
        OperatingMode, PolicyBoundaryAssessment, ProgressiveAuthorityEvidenceV1,
    },
    reconciliation::{DriftClass, DriftState},
    rollout::{
        partial_acceptance_signing_bytes, validate_manifest, FailurePolicy, OperationRunV1,
        PartialAcceptanceV1, RolloutStore, RolloutTargetV1, RunState, TargetRunState,
        PARTIAL_ACCEPTANCE_SCHEMA, ROLLOUT_SCHEMA,
    },
    ConvergenceState, Operation, Plan, PolicyDecision, PLANNER_VERSION,
};

fn sha(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn inspection(
    now: u64,
    digest_value: Option<String>,
    generation: Option<u64>,
) -> AdapterInspectionV1 {
    AdapterInspectionV1 {
        schema_version: "1".into(),
        evidence_class: "adapter_host_observation".into(),
        evidence_source: "domain_local_adapter_host".into(),
        authorizes_mutation: false,
        observed_at: now,
        expires_at: now + 60,
        entries: vec![AdapterInspectionEntryV1 {
            target_id: "target:0".into(),
            registered_capability: "synthetic-v1".into(),
            advertised_capabilities: vec!["synthetic-v1".into()],
            descriptor_digest: sha('e'),
            observation_digest: digest_value,
            observed_generation: generation,
            convergence_state: None,
            reason_code: "OBSERVED".into(),
        }],
        extensions: vec![],
    }
}

fn converged_single_store(path: &std::path::Path, now: u64) -> RolloutStore {
    let mut store = RolloutStore::open(path).unwrap();
    store.create(&manifest(1, now), now).unwrap();
    store.mark_running("run:test", "target:0", now).unwrap();
    let mut lifecycle = receipt("operation:0", ExecutionState::Converged);
    lifecycle.verification_receipt = Some(AdapterReceipt {
        operation_id: "operation:0".into(),
        state: ConvergenceState::Converged,
        generation: 1,
        result_digest: manifest(1, now).targets[0]
            .gate
            .operation
            .desired_digest
            .clone(),
        reason: "VERIFIED".into(),
    });
    store
        .record_receipt("run:test", "target:0", &lifecycle, now + 1)
        .unwrap();
    store
}
fn sign_request(key: &SigningKey, request: &mut ManagementRequest) {
    let mut value = serde_json::to_value(&*request).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    request.signature = STANDARD.encode(key.sign(&serde_jcs::to_vec(&value).unwrap()).to_bytes());
}
fn sign_authorization(key: &SigningKey, value: &mut ApplyAuthorizationEvidenceV1) {
    value.signature = STANDARD.encode(
        key.sign(&authorization_signing_bytes(value).unwrap())
            .to_bytes(),
    );
}

fn gate(key: &SigningKey, id: usize, now: u64) -> LocalApplyGateV1 {
    let target = format!("target:{id}");
    let operation_id = format!("operation:{id}");
    let desired = serde_json::json!({"enabled":true,"target":id});
    let desired_digest = digest(&desired).unwrap();
    let plan = Plan {
        schema_version: "1".into(),
        planner_version: PLANNER_VERSION.into(),
        bundle_id: format!("bundle:{id}"),
        bundle_digest: sha('a'),
        expected_generation: 0,
        target_generation: 1,
        operations: vec![Operation {
            operation_id: operation_id.clone(),
            resource_id: target.clone(),
            action: "update".into(),
            before_digest: sha('b'),
            after_digest: desired_digest.clone(),
            expected_generation: 0,
            target_generation: 1,
            idempotency_key: format!("idempotency:{id}"),
        }],
    };
    let plan_digest = digest(&plan).unwrap();
    let operation = AdapterOperation {
        operation_id: operation_id.clone(),
        target_id: target.clone(),
        action: "apply".into(),
        plan_digest: plan_digest.clone(),
        desired_digest: desired_digest.clone(),
        expected_generation: 1,
        expires_at: now + 60,
        capability: "synthetic-v1".into(),
        desired,
        related_operation_id: None,
    };
    let mut authorization = ApplyAuthorizationEvidenceV1 {
        schema_version: "1".into(),
        authorization_id: format!("authorization:{id}"),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        mode: OperatingMode::Confirm,
        plan_digest: plan_digest.clone(),
        operation_digest: digest(&operation).unwrap(),
        policy_generation: 4,
        fact_snapshot_digest: sha('d'),
        policy_boundary: PolicyBoundaryAssessment::Satisfied,
        proposed_decision: PolicyDecision::Allow,
        issued_at: now,
        expires_at: now + 60,
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign_authorization(key, &mut authorization);
    let progressive_authority = ProgressiveAuthorityEvidenceV1 {
        schema_version: "1".into(),
        evidence_id: format!("evidence:{id}"),
        mode: OperatingMode::Confirm,
        application_id: "application:test".into(),
        intent: "urn:iicp:intent:test:v1".into(),
        policy_generation: 4,
        fact_snapshot_digest: sha('d'),
        observed_at: now,
        actual_decision: None,
        proposed_decision: Some(PolicyDecision::Allow),
        plan_digest: Some(plan_digest.clone()),
        authorization_evidence_digest: Some(digest(&authorization).unwrap()),
        policy_boundary: PolicyBoundaryAssessment::Satisfied,
        may_request_apply: true,
        extensions: vec![],
    };
    let mut request = ManagementRequest {
        schema_version: "1".into(),
        request_id: operation_id,
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        action: "apply".into(),
        resource_ids: vec![target],
        payload_digest: desired_digest,
        plan_digest,
        expected_generation: 1,
        issued_at: now,
        expires_at: now + 60,
        nonce: format!("nonce:{id}"),
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign_request(key, &mut request);
    LocalApplyGateV1 {
        schema_version: APPLY_GATE_SCHEMA.into(),
        request,
        plan,
        operation,
        progressive_authority,
        authorization,
    }
}

fn reconciliation_gate(key: &SigningKey, now: u64, observed_generation: u64) -> LocalApplyGateV1 {
    let mut value = gate(key, 0, now);
    let operation_id = "operation:reconcile:0".to_string();
    value.operation.operation_id = operation_id.clone();
    value.operation.expected_generation = observed_generation;
    value.operation.related_operation_id = Some("operation:0".into());
    value.plan.operations[0].operation_id = operation_id.clone();
    value.plan.operations[0].target_generation = observed_generation;
    value.plan.operations[0].expected_generation = observed_generation;
    let plan_digest = digest(&value.plan).unwrap();
    value.operation.plan_digest = plan_digest.clone();
    value.request.request_id = operation_id;
    value.request.plan_digest = plan_digest.clone();
    value.request.nonce = "nonce:reconcile:0".into();
    value.authorization.authorization_id = "authorization:reconcile:0".into();
    value.authorization.plan_digest = plan_digest;
    value.authorization.operation_digest = digest(&value.operation).unwrap();
    value.authorization.signature.clear();
    sign_authorization(key, &mut value.authorization);
    value.progressive_authority.plan_digest = Some(value.request.plan_digest.clone());
    value.progressive_authority.authorization_evidence_digest =
        Some(digest(&value.authorization).unwrap());
    value.request.signature.clear();
    sign_request(key, &mut value.request);
    value
}
fn manifest(count: usize, now: u64) -> OperationRunV1 {
    let key = SigningKey::from_bytes(&[41; 32]);
    OperationRunV1 {
        schema_version: ROLLOUT_SCHEMA.into(),
        run_id: "run:test".into(),
        administrative_domain: "domain:test".into(),
        audience: "controller:test".into(),
        failure_policy: FailurePolicy::ContinueIndependent,
        created_at: now,
        expires_at: now + 60,
        targets: (0..count)
            .map(|id| RolloutTargetV1 {
                target_id: format!("target:{id}"),
                executor_ref: format!("executor:{}", id % 2),
                batch: if id == 0 { 0 } else { 1 },
                required: true,
                gate: gate(&key, id, now),
            })
            .collect(),
        authorizes_target_execution: false,
    }
}
fn receipt(operation_id: &str, state: ExecutionState) -> ApplyLifecycleReceiptV1 {
    let mut r = ApplyLifecycleReceiptV1::failure(operation_id, "TEST");
    r.state = state;
    r.retry = RetryDisposition::NotNeeded;
    r
}

fn sign_acceptance(key: &SigningKey, value: &mut PartialAcceptanceV1) {
    value.signature = STANDARD.encode(
        key.sign(&partial_acceptance_signing_bytes(value).unwrap())
            .to_bytes(),
    );
}

#[test]
fn manifest_requires_one_required_canary_and_contiguous_batches() {
    let now = 1_700_000_000;
    let good = manifest(3, now);
    assert!(validate_manifest(&good, now).is_ok());
    let mut bad = good.clone();
    bad.targets[1].batch = 2;
    bad.targets[2].batch = 2;
    assert_eq!(
        validate_manifest(&bad, now).unwrap_err(),
        "ROLLOUT_BATCH_SEQUENCE_INVALID"
    );
    let mut bad = good;
    bad.targets[0].required = false;
    assert_eq!(
        validate_manifest(&bad, now).unwrap_err(),
        "ROLLOUT_CANARY_INVALID"
    );
}

#[test]
fn durable_batches_resume_and_end_partially_converged() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollout.db");
    let value = manifest(10, now);
    {
        let mut store = RolloutStore::open(&path).unwrap();
        let first = store.create(&value, now).unwrap();
        assert_eq!(first.state, RunState::Pending);
        assert_eq!(
            store.create(&value, now).unwrap().manifest_digest,
            first.manifest_digest
        );
        store.mark_running("run:test", "target:0", now).unwrap();
    }
    let mut store = RolloutStore::open(&path).unwrap();
    assert_eq!(store.runnable_targets("run:test").unwrap().len(), 1);
    let r = receipt("operation:0", ExecutionState::Converged);
    let advanced = store
        .record_receipt("run:test", "target:0", &r, now + 1)
        .unwrap();
    assert_eq!(advanced.current_batch, 1);
    for id in 1..10 {
        store
            .mark_running("run:test", &format!("target:{id}"), now + 2)
            .unwrap();
        let state = if id == 9 {
            ExecutionState::Deferred
        } else {
            ExecutionState::Converged
        };
        let status = store
            .record_receipt(
                "run:test",
                &format!("target:{id}"),
                &receipt(&format!("operation:{id}"), state),
                now + 2,
            )
            .unwrap();
        if id == 9 {
            assert_eq!(status.state, RunState::PartiallyConverged);
        }
    }
    let status = store.status("run:test").unwrap();
    assert_eq!(
        status
            .targets
            .iter()
            .filter(|t| t.state == TargetRunState::Converged)
            .count(),
        9
    );
    assert!(!status.partial_accepted);
}

#[test]
fn canary_failure_holds_later_batches_and_retry_is_explicit() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let mut store = RolloutStore::open(&dir.path().join("r.db")).unwrap();
    store.create(&manifest(3, now), now).unwrap();
    store.mark_running("run:test", "target:0", now).unwrap();
    let status = store
        .record_execution_error("run:test", "target:0", "UNREACHABLE", now + 1)
        .unwrap();
    assert_eq!(status.state, RunState::Paused);
    assert!(store.runnable_targets("run:test").is_err());
    let target = store
        .prepare_retry("run:test", "target:0", now + 2)
        .unwrap();
    assert_eq!(target.target_id, "target:0");
}

#[test]
fn receipt_cannot_be_substituted_or_replayed_after_completion() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let mut store = RolloutStore::open(&dir.path().join("r.db")).unwrap();
    store.create(&manifest(2, now), now).unwrap();
    store.mark_running("run:test", "target:0", now).unwrap();
    assert_eq!(
        store
            .record_receipt(
                "run:test",
                "target:0",
                &receipt("operation:1", ExecutionState::Converged),
                now
            )
            .unwrap_err(),
        "ROLLOUT_RECEIPT_BINDING_INVALID"
    );
    store
        .record_receipt(
            "run:test",
            "target:0",
            &receipt("operation:0", ExecutionState::Converged),
            now,
        )
        .unwrap();
    assert_eq!(
        store
            .record_receipt(
                "run:test",
                "target:0",
                &receipt("operation:0", ExecutionState::Converged),
                now
            )
            .unwrap_err(),
        "ROLLOUT_TARGET_NOT_RUNNABLE"
    );
}

#[test]
fn partial_acceptance_is_signed_and_version_bound() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let mut store = RolloutStore::open(&dir.path().join("r.db")).unwrap();
    store.create(&manifest(2, now), now).unwrap();
    for (id, state) in [
        (0, ExecutionState::Converged),
        (1, ExecutionState::Deferred),
    ] {
        store
            .mark_running("run:test", &format!("target:{id}"), now)
            .unwrap();
        store
            .record_receipt(
                "run:test",
                &format!("target:{id}"),
                &receipt(&format!("operation:{id}"), state),
                now + 1,
            )
            .unwrap();
    }
    let status = store.status("run:test").unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let mut acceptance = PartialAcceptanceV1 {
        schema_version: PARTIAL_ACCEPTANCE_SCHEMA.into(),
        acceptance_id: "acceptance:1".into(),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        run_id: status.run_id.clone(),
        manifest_digest: status.manifest_digest.clone(),
        expected_run_version: status.version,
        issued_at: now + 1,
        expires_at: now + 30,
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign_acceptance(&key, &mut acceptance);
    let accepted = store
        .accept_partial(&acceptance, key.verifying_key().to_bytes(), now + 2)
        .unwrap();
    assert!(accepted.partial_accepted);
    assert_eq!(
        store
            .accept_partial(&acceptance, key.verifying_key().to_bytes(), now + 2)
            .unwrap_err(),
        "PARTIAL_ACCEPTANCE_INVALID"
    );
}

#[test]
fn published_schema_accepts_manifest_status_and_acceptance() {
    let now = 1_700_000_000;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-rollout-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let run = manifest(2, now);
    assert!(validator.is_valid(&serde_json::to_value(&run).unwrap()));
    let dir = tempfile::tempdir().unwrap();
    let mut store = RolloutStore::open(&dir.path().join("r.db")).unwrap();
    let status = store.create(&run, now).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(status).unwrap()));
    let acceptance = PartialAcceptanceV1 {
        schema_version: PARTIAL_ACCEPTANCE_SCHEMA.into(),
        acceptance_id: "acceptance:1".into(),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        run_id: "run:test".into(),
        manifest_digest: "sha256:test".into(),
        expected_run_version: 1,
        issued_at: now,
        expires_at: now + 1,
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: "signature".into(),
    };
    assert!(validator.is_valid(&serde_json::to_value(acceptance).unwrap()));
}

#[test]
fn drift_assessment_is_durable_and_missing_evidence_is_unknown() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.db");
    let mut store = converged_single_store(&path, now);
    let output = store
        .assess_drift("run:test", &inspection(now + 2, None, None), now + 2)
        .unwrap();
    assert_eq!(output.assessments[0].state, DriftState::Unknown);
    assert!(!output.authorizes_mutation);
    drop(store);
    let reopened = RolloutStore::open(&path)
        .unwrap()
        .drift_status("run:test")
        .unwrap();
    assert_eq!(reopened.assessments, output.assessments);
}

#[test]
fn exact_and_changed_observations_are_distinguished() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let mut store = converged_single_store(&dir.path().join("r.db"), now);
    let expected = manifest(1, now).targets[0]
        .gate
        .operation
        .desired_digest
        .clone();
    let current = store
        .assess_drift(
            "run:test",
            &inspection(now + 2, Some(expected), Some(1)),
            now + 2,
        )
        .unwrap();
    assert_eq!(current.assessments[0].state, DriftState::InSync);
    let changed = store
        .assess_drift(
            "run:test",
            &inspection(now + 3, Some(sha('f')), Some(2)),
            now + 3,
        )
        .unwrap();
    assert_eq!(changed.assessments[0].state, DriftState::Drifted);
}

#[test]
fn only_bounded_classes_create_non_authorizing_proposals() {
    let now = 1_700_000_000;
    let dir = tempfile::tempdir().unwrap();
    let mut store = converged_single_store(&dir.path().join("r.db"), now);
    store
        .assess_drift(
            "run:test",
            &inspection(now + 2, Some(sha('f')), Some(2)),
            now + 2,
        )
        .unwrap();
    assert_eq!(
        store
            .create_reconciliation_proposal(
                "run:test",
                "target:0",
                DriftClass::TrustIdentity,
                now + 3
            )
            .unwrap_err(),
        "RECONCILIATION_CLASS_REVIEW_REQUIRED"
    );
    let proposal = store
        .create_reconciliation_proposal(
            "run:test",
            "target:0",
            DriftClass::CapabilityRuntime,
            now + 3,
        )
        .unwrap();
    assert!(!proposal.authorizes_mutation);
    assert!(proposal.requires_fresh_apply_gate);
    assert_eq!(proposal.expected_observed_generation, 2);
    assert_eq!(
        store
            .create_reconciliation_proposal(
                "run:test",
                "target:0",
                DriftClass::SafeMetadata,
                now + 100,
            )
            .unwrap_err(),
        "RECONCILIATION_INVALID"
    );
    let original_gate = manifest(1, now).targets.into_iter().next().unwrap().gate;
    assert_eq!(
        store
            .validate_reconciliation_gate(&proposal.proposal_id, &original_gate, now + 3)
            .unwrap_err(),
        "RECONCILIATION_GATE_BINDING_INVALID"
    );
    let key = SigningKey::from_bytes(&[41; 32]);
    let fresh = reconciliation_gate(&key, now, 2);
    assert_eq!(
        store
            .validate_reconciliation_gate(&proposal.proposal_id, &fresh, now + 3)
            .unwrap()
            .proposal_id,
        proposal.proposal_id
    );
}

#[test]
fn reconciliation_schema_accepts_public_projections() {
    let now = 1_700_000_000;
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-reconciliation-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store = converged_single_store(&dir.path().join("r.db"), now);
    let status = store
        .assess_drift(
            "run:test",
            &inspection(now + 2, Some(sha('f')), Some(2)),
            now + 2,
        )
        .unwrap();
    assert!(validator.is_valid(&serde_json::to_value(&status.assessments[0]).unwrap()));
    assert!(validator.is_valid(&serde_json::to_value(&status).unwrap()));
    let proposal = store
        .create_reconciliation_proposal("run:test", "target:0", DriftClass::SafeMetadata, now + 3)
        .unwrap();
    assert!(validator.is_valid(&serde_json::to_value(proposal).unwrap()));
}
