use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::{
    adapters::AdapterOperation,
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
    rollout::{
        partial_acceptance_signing_bytes, validate_manifest, FailurePolicy, OperationRunV1,
        PartialAcceptanceV1, RolloutStore, RolloutTargetV1, RunState, TargetRunState,
        PARTIAL_ACCEPTANCE_SCHEMA, ROLLOUT_SCHEMA,
    },
    Operation, Plan, PolicyDecision, PLANNER_VERSION,
};

fn sha(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
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
