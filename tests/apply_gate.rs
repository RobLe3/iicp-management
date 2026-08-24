use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::{
    adapters::AdapterOperation,
    apply_gate::{
        authorization_signing_bytes, preview_apply, validate_apply_gate,
        ApplyAuthorizationEvidenceV1, ApplyGateError, LocalApplyGateV1, APPLY_GATE_SCHEMA,
    },
    controller::{
        Controller, ControllerError, ControllerPolicy, DecisionState, ManagementRequest,
        SIGNATURE_PROFILE,
    },
    digest,
    progressive_authority::{
        OperatingMode, PolicyBoundaryAssessment, ProgressiveAuthorityEvidenceV1,
    },
    Operation, Plan, PolicyDecision, PLANNER_VERSION,
};
use std::collections::BTreeSet;

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
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

fn gate(key: &SigningKey, mode: OperatingMode, now: u64) -> LocalApplyGateV1 {
    let desired = serde_json::json!({"enabled":true});
    let desired_digest = digest(&desired).unwrap();
    let plan = Plan {
        schema_version: "1".into(),
        planner_version: PLANNER_VERSION.into(),
        bundle_id: "bundle:finance".into(),
        bundle_digest: sha('a'),
        expected_generation: 0,
        target_generation: 1,
        operations: vec![Operation {
            operation_id: "operation:finance".into(),
            resource_id: "target:finance".into(),
            action: "update".into(),
            before_digest: sha('b'),
            after_digest: desired_digest.clone(),
            expected_generation: 0,
            target_generation: 1,
            idempotency_key: "idempotency:finance".into(),
        }],
    };
    let plan_digest = digest(&plan).unwrap();
    let operation = AdapterOperation {
        operation_id: "operation:finance".into(),
        target_id: "target:finance".into(),
        action: "apply".into(),
        plan_digest: plan_digest.clone(),
        desired_digest,
        expected_generation: 1,
        expires_at: now + 60,
        capability: "synthetic-v1".into(),
        desired,
        related_operation_id: None,
    };
    let mut authorization = ApplyAuthorizationEvidenceV1 {
        schema_version: "1".into(),
        authorization_id: "authorization:finance".into(),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        mode: mode.clone(),
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
        evidence_id: "evidence:finance".into(),
        mode,
        application_id: "application:finance".into(),
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
        request_id: operation.operation_id.clone(),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        action: "apply".into(),
        resource_ids: vec![operation.target_id.clone()],
        payload_digest: operation.desired_digest.clone(),
        plan_digest,
        expected_generation: 1,
        issued_at: now,
        expires_at: now + 60,
        nonce: "nonce:finance".into(),
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

fn policy(now: u64) -> ControllerPolicy {
    ControllerPolicy {
        audience: "controller:test".into(),
        domain: "domain:test".into(),
        allowed_actions: BTreeSet::from(["apply".into()]),
        revocation_checkpoint: now,
        max_checkpoint_age: 3600,
        high_impact_actions: BTreeSet::from(["apply".into()]),
        max_decision_events: 100,
    }
}

fn controller_at_generation_one(path: &std::path::Path, key: &SigningKey, now: u64) -> Controller {
    let controller = Controller::open(path, policy(now), key.verifying_key().to_bytes()).unwrap();
    let mut seed = gate(key, OperatingMode::Confirm, now).request;
    seed.action = "observe".into();
    seed.resource_ids = vec!["seed".into()];
    seed.payload_digest = sha('e');
    seed.plan_digest = sha('f');
    seed.expected_generation = 0;
    seed.request_id = "seed".into();
    seed.nonce = "nonce:seed".into();
    sign_request(key, &mut seed);
    let mut seed_policy = policy(now);
    seed_policy.allowed_actions.insert("observe".into());
    drop(controller);
    let mut controller =
        Controller::open(path, seed_policy, key.verifying_key().to_bytes()).unwrap();
    controller.evaluate(&seed, now).unwrap();
    controller
}

#[test]
fn preview_exposes_exact_change_without_authorizing_a_target_effect() {
    let key = SigningKey::from_bytes(&[71; 32]);
    let now = Controller::now();
    let preview = preview_apply(&gate(&key, OperatingMode::Confirm, now), now).unwrap();
    assert_eq!(preview.target_id, "target:finance");
    assert_eq!(preview.action, "apply");
    assert_eq!(preview.before_digest, sha('b'));
    assert_eq!(
        preview.after_digest,
        digest(&serde_json::json!({"enabled":true})).unwrap()
    );
    assert_eq!(preview.controller_generation, 1);
    assert_eq!(preview.policy_generation, 4);
}

#[test]
fn observe_recommend_and_unsatisfied_policy_cannot_request_apply() {
    let key = SigningKey::from_bytes(&[72; 32]);
    let now = Controller::now();
    for mode in [OperatingMode::Observe, OperatingMode::Recommend] {
        assert_eq!(
            validate_apply_gate(&gate(&key, mode, now), now),
            Err(ApplyGateError::ModeNotAuthorized)
        );
    }
    let mut failed = gate(&key, OperatingMode::Confirm, now);
    failed.authorization.policy_boundary = PolicyBoundaryAssessment::Failed;
    assert!(validate_apply_gate(&failed, now).is_err());
}

#[test]
fn exact_gate_is_authorized_once_without_invoking_an_adapter() {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[73; 32]);
    let now = Controller::now();
    let mut controller =
        controller_at_generation_one(&directory.path().join("controller.db"), &key, now);
    let value = gate(&key, OperatingMode::Confirm, now);
    let (receipt, operation) = controller.authorize_apply_gate(&value, now).unwrap();
    assert_eq!(receipt.decision, DecisionState::Accepted);
    assert_eq!(receipt.controller_generation, Some(2));
    assert_eq!(receipt.target_effect, "not_attempted");
    assert_eq!(receipt.convergence, "not_evaluated");
    assert_eq!(operation.operation().operation_id, "operation:finance");
    assert!(matches!(
        controller.authorize_apply_gate(&value, now),
        Err(ControllerError::Replay)
    ));
}

#[test]
fn concurrent_apply_authorizations_have_one_controller_winner() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let key = SigningKey::from_bytes(&[78; 32]);
    let now = Controller::now();
    let controller = controller_at_generation_one(&database, &key, now);
    drop(controller);
    let first = gate(&key, OperatingMode::AutomaticWithinPolicy, now);
    let mut second = first.clone();
    second.request.nonce = "nonce:finance:second".into();
    sign_request(&key, &mut second.request);
    let barrier = Arc::new(Barrier::new(2));
    let handles = [first, second].map(|value| {
        let database = database.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        thread::spawn(move || {
            let mut controller =
                Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
            barrier.wait();
            controller.authorize_apply_gate(&value, now)
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let controller =
        Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
    assert_eq!(controller.generation().unwrap(), 2);
}

#[test]
fn authority_and_operation_tamper_fail_before_generation_changes() {
    type Mutation = Box<dyn Fn(&mut LocalApplyGateV1)>;
    let key = SigningKey::from_bytes(&[74; 32]);
    let now = Controller::now();
    let mutations: Vec<Mutation> = vec![
        Box::new(|v| v.operation.target_id = "target:other".into()),
        Box::new(|v| v.operation.desired_digest = sha('9')),
        Box::new(|v| v.authorization.audience = "controller:other".into()),
        Box::new(|v| v.progressive_authority.policy_generation += 1),
        Box::new(|v| v.authorization.expires_at = 0),
    ];
    for mutate in mutations {
        let directory = tempfile::tempdir().unwrap();
        let mut controller =
            controller_at_generation_one(&directory.path().join("controller.db"), &key, now);
        let mut value = gate(&key, OperatingMode::Confirm, now);
        mutate(&mut value);
        assert!(controller.authorize_apply_gate(&value, now).is_err());
        assert_eq!(controller.generation().unwrap(), 1);
    }
}

#[test]
fn authorization_signature_is_independently_verified() {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[75; 32]);
    let now = Controller::now();
    let mut controller =
        controller_at_generation_one(&directory.path().join("controller.db"), &key, now);
    let mut value = gate(&key, OperatingMode::AutomaticWithinPolicy, now);
    value.authorization.signature = STANDARD.encode([0_u8; 64]);
    value.progressive_authority.authorization_evidence_digest =
        Some(digest(&value.authorization).unwrap());
    assert!(matches!(
        controller.authorize_apply_gate(&value, now),
        Err(ControllerError::Signature)
    ));
    assert_eq!(controller.generation().unwrap(), 1);
}

#[test]
fn published_schema_and_cli_preview_are_stable() {
    use std::{fs, process::Command};

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../contracts/local-apply-gate-v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let key = SigningKey::from_bytes(&[76; 32]);
    let now = Controller::now();
    let value = gate(&key, OperatingMode::Confirm, now);
    assert!(validator.is_valid(&serde_json::to_value(&value).unwrap()));

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("apply.json");
    fs::write(&input, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let preview = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args(["--json", "preview-apply", input.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(preview.status.success());
    let output: serde_json::Value = serde_json::from_slice(&preview.stdout).unwrap();
    assert_eq!(output["target_id"], "target:finance");
    assert_eq!(output["before_digest"], sha('b'));
    assert_eq!(
        output["after_digest"],
        digest(&serde_json::json!({"enabled":true})).unwrap()
    );

    let missing_confirmation = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "request-apply",
            directory.path().join("missing.sock").to_str().unwrap(),
            input.to_str().unwrap(),
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_confirmation.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&missing_confirmation.stderr)
        .contains("APPLY_CONFIRMATION_REQUIRED"));
}

#[cfg(unix)]
#[test]
fn confirmed_cli_request_is_authorized_over_ipc_without_target_execution() {
    use std::process::{Command, Stdio};
    use std::{fs, thread, time::Duration};

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let socket = directory.path().join("controller.sock");
    let public_key = directory.path().join("operator.pub");
    let input = directory.path().join("apply.json");
    let key = SigningKey::from_bytes(&[77; 32]);
    let now = Controller::now();
    let controller = controller_at_generation_one(&database, &key, now);
    drop(controller);
    fs::write(&public_key, key.verifying_key().to_bytes()).unwrap();
    fs::write(
        &input,
        serde_json::to_vec_pretty(&gate(&key, OperatingMode::Confirm, now)).unwrap(),
    )
    .unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_iicp-management-controller"))
        .args([
            "serve",
            socket.to_str().unwrap(),
            database.to_str().unwrap(),
            public_key.to_str().unwrap(),
            "controller:test",
            "domain:test",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "request-apply",
            socket.to_str().unwrap(),
            input.to_str().unwrap(),
            "--confirm",
            "operation:finance",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["decision"], "accepted");
    assert_eq!(receipt["target_effect"], "not_attempted");
    assert_eq!(receipt["convergence"], "not_evaluated");
    server.kill().unwrap();
    server.wait().unwrap();
}
