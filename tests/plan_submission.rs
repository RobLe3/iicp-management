use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::{
    controller::{
        validate_plan_submission, Controller, ControllerError, ControllerPolicy, DecisionState,
        LocalPlanSubmissionV1, ManagementRequest, PLAN_ACCEPT_ACTION, PLAN_SUBMISSION_SCHEMA,
        SIGNATURE_PROFILE,
    },
    digest, Operation, Plan, PLANNER_VERSION,
};
use std::collections::BTreeSet;

fn sign(key: &SigningKey, request: &mut ManagementRequest) {
    let mut value = serde_json::to_value(&*request).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    request.signature = STANDARD.encode(key.sign(&serde_jcs::to_vec(&value).unwrap()).to_bytes());
}

fn submission(key: &SigningKey, nonce: &str, now: u64) -> LocalPlanSubmissionV1 {
    let plan = Plan {
        schema_version: "1".into(),
        planner_version: PLANNER_VERSION.into(),
        bundle_id: "bundle:finance".into(),
        bundle_digest: format!("sha256:{}", "a".repeat(64)),
        expected_generation: 0,
        target_generation: 1,
        operations: vec![Operation {
            operation_id: "operation:finance".into(),
            resource_id: "policy:finance".into(),
            action: "update".into(),
            before_digest: format!("sha256:{}", "b".repeat(64)),
            after_digest: format!("sha256:{}", "c".repeat(64)),
            expected_generation: 0,
            target_generation: 1,
            idempotency_key: "idempotency:finance".into(),
        }],
    };
    let mut request = ManagementRequest {
        schema_version: "1".into(),
        request_id: "request:finance".into(),
        issuer_id: "operator:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        action: PLAN_ACCEPT_ACTION.into(),
        resource_ids: vec!["policy:finance".into()],
        payload_digest: plan.bundle_digest.clone(),
        plan_digest: digest(&plan).unwrap(),
        expected_generation: 0,
        issued_at: now,
        expires_at: now + 60,
        nonce: nonce.into(),
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign(key, &mut request);
    LocalPlanSubmissionV1 {
        schema_version: PLAN_SUBMISSION_SCHEMA.into(),
        request,
        plan,
    }
}

fn policy(now: u64) -> ControllerPolicy {
    ControllerPolicy {
        audience: "controller:test".into(),
        domain: "domain:test".into(),
        allowed_actions: BTreeSet::from([PLAN_ACCEPT_ACTION.into()]),
        revocation_checkpoint: now,
        max_checkpoint_age: 3600,
        high_impact_actions: BTreeSet::from([PLAN_ACCEPT_ACTION.into()]),
        max_decision_events: 100,
    }
}

#[test]
fn exact_plan_is_accepted_without_claiming_a_target_effect() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let key = SigningKey::from_bytes(&[61; 32]);
    let now = Controller::now();
    let mut controller =
        Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
    let receipt = controller
        .accept_plan_submission(&submission(&key, "nonce:one", now), now)
        .unwrap();
    assert_eq!(receipt.decision, DecisionState::Accepted);
    assert_eq!(receipt.controller_generation, Some(1));
    assert_eq!(receipt.target_effect, "not_attempted");
    assert_eq!(receipt.convergence, "not_evaluated");
    assert_eq!(controller.generation().unwrap(), 1);
    drop(controller);
    let mut restarted =
        Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
    assert!(matches!(
        restarted.accept_plan_submission(&submission(&key, "nonce:one", now), now),
        Err(ControllerError::Replay)
    ));
    assert_eq!(restarted.generation().unwrap(), 1);
}

#[test]
fn binding_tamper_fails_before_controller_state_changes() {
    type Mutation = Box<dyn Fn(&mut LocalPlanSubmissionV1)>;
    let key = SigningKey::from_bytes(&[62; 32]);
    let now = Controller::now();
    let variants: Vec<Mutation> = vec![
        Box::new(|s| s.plan.operations[0].after_digest.push('x')),
        Box::new(|s| s.request.payload_digest.push('x')),
        Box::new(|s| s.request.resource_ids = vec!["policy:other".into()]),
        Box::new(|s| s.request.action = "apply".into()),
        Box::new(|s| s.request.expected_generation = 1),
        Box::new(|s| s.plan.target_generation = 2),
    ];
    for (index, mutate) in variants.into_iter().enumerate() {
        let directory = tempfile::tempdir().unwrap();
        let mut controller = Controller::open(
            &directory.path().join("controller.db"),
            policy(now),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut value = submission(&key, &format!("nonce:{index}"), now);
        mutate(&mut value);
        assert!(matches!(
            controller.accept_plan_submission(&value, now),
            Err(ControllerError::Invalid("plan_binding"))
        ));
        assert_eq!(controller.generation().unwrap(), 0);
    }
}

#[test]
fn signature_policy_time_generation_and_replay_checks_remain_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[63; 32]);
    let now = Controller::now();
    let mut controller = Controller::open(
        &directory.path().join("controller.db"),
        policy(now),
        key.verifying_key().to_bytes(),
    )
    .unwrap();

    let exact = submission(&key, "nonce:exact", now);
    controller.accept_plan_submission(&exact, now).unwrap();
    assert!(matches!(
        controller.accept_plan_submission(&exact, now),
        Err(ControllerError::Replay)
    ));
    let stale = submission(&key, "nonce:stale", now);
    assert!(matches!(
        controller.accept_plan_submission(&stale, now),
        Err(ControllerError::Generation)
    ));
    let mut bad_signature = submission(&key, "nonce:signature", now);
    bad_signature.request.signature = STANDARD.encode([0_u8; 64]);
    assert!(matches!(
        controller.accept_plan_submission(&bad_signature, now),
        Err(ControllerError::Signature)
    ));

    for (nonce, mutate) in [
        ("nonce:audience", "audience"),
        ("nonce:domain", "domain"),
        ("nonce:expired", "expired"),
        ("nonce:generation", "generation"),
    ] {
        let mut value = submission(&key, nonce, now);
        value.plan.expected_generation = 1;
        value.plan.target_generation = 2;
        value.plan.operations[0].expected_generation = 1;
        value.plan.operations[0].target_generation = 2;
        value.request.expected_generation = 1;
        value.request.plan_digest = digest(&value.plan).unwrap();
        match mutate {
            "audience" => value.request.audience = "controller:other".into(),
            "domain" => value.request.administrative_domain = "domain:other".into(),
            "expired" => {
                value.request.issued_at = now - 100;
                value.request.expires_at = now - 1;
            }
            "generation" => value.request.expected_generation = 2,
            _ => unreachable!(),
        }
        sign(&key, &mut value.request);
        assert!(controller.accept_plan_submission(&value, now).is_err());
        assert_eq!(controller.generation().unwrap(), 1);
    }

    let stale_directory = tempfile::tempdir().unwrap();
    let mut stale_policy = policy(now);
    stale_policy.revocation_checkpoint = now.saturating_sub(3601);
    let mut stale_controller = Controller::open(
        &stale_directory.path().join("controller.db"),
        stale_policy,
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(matches!(
        stale_controller
            .accept_plan_submission(&submission(&key, "nonce:stale-revocation", now), now),
        Err(ControllerError::Policy)
    ));
}

#[test]
fn concurrent_exact_submissions_have_one_generation_winner() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("controller.db");
    let key = SigningKey::from_bytes(&[67; 32]);
    let now = Controller::now();
    Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles = ["nonce:concurrent-a", "nonce:concurrent-b"].map(|nonce| {
        let database = database.clone();
        let barrier = barrier.clone();
        let key = key.clone();
        thread::spawn(move || {
            let mut controller =
                Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
            barrier.wait();
            controller.accept_plan_submission(&submission(&key, nonce, now), now)
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let controller =
        Controller::open(&database, policy(now), key.verifying_key().to_bytes()).unwrap();
    assert_eq!(controller.generation().unwrap(), 1);
}

#[test]
fn duplicate_resources_and_unknown_fields_are_rejected() {
    let key = SigningKey::from_bytes(&[64; 32]);
    let now = Controller::now();
    let mut value = submission(&key, "nonce:duplicate", now);
    value.plan.operations.push(value.plan.operations[0].clone());
    value.request.plan_digest = digest(&value.plan).unwrap();
    sign(&key, &mut value.request);
    assert!(validate_plan_submission(&value).is_err());

    let mut json = serde_json::to_value(submission(&key, "nonce:unknown", now)).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("extra".into(), true.into());
    assert!(serde_json::from_value::<LocalPlanSubmissionV1>(json).is_err());
}

#[test]
fn published_submission_schema_accepts_the_exact_wire_shape() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/local-plan-submission-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    let value = serde_json::to_value(submission(&key, "nonce:schema", Controller::now())).unwrap();
    assert!(validator.is_valid(&value));

    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), true.into());
    assert!(!validator.is_valid(&unknown));
    let mut wrong_action = value;
    wrong_action["request"]["action"] = "apply".into();
    assert!(!validator.is_valid(&wrong_action));
}

#[cfg(unix)]
#[test]
fn operator_cli_submits_over_owner_protected_ipc_and_reports_no_target_effect() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::{fs, thread, time::Duration};

    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("controller.sock");
    let database = directory.path().join("controller.db");
    let public_key = directory.path().join("operator.pub");
    let input = directory.path().join("submission.json");
    let key = SigningKey::from_bytes(&[65; 32]);
    fs::write(&public_key, key.verifying_key().to_bytes()).unwrap();
    fs::write(
        &input,
        serde_json::to_vec_pretty(&submission(&key, "nonce:cli", Controller::now())).unwrap(),
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
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let output = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "submit-plan",
            socket.to_str().unwrap(),
            input.to_str().unwrap(),
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

    let replay = Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "submit-plan",
            socket.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(3));
    let replay_receipt: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay_receipt["decision"], "rejected");
    assert_eq!(replay_receipt["reason"], "REQUEST_REPLAY");

    server.kill().unwrap();
    server.wait().unwrap();
}
