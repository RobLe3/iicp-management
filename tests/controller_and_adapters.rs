use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_client::runtime_config::{OperatingMode, RuntimeConfigV1, SecretRef};
use iicp_management_core::{adapters::*, controller::*, digest, ConvergenceState};
use serde_json::{json, Value};
use std::collections::BTreeSet;
fn request(key: &SigningKey, nonce: &str, generation: u64, now: u64) -> ManagementRequest {
    let mut r = ManagementRequest {
        schema_version: "1".into(),
        request_id: format!("r-{nonce}"),
        issuer_id: "issuer".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        action: "apply".into(),
        resource_ids: vec!["node:a".into()],
        payload_digest: "sha256:payload".into(),
        plan_digest: "sha256:plan".into(),
        expected_generation: generation,
        issued_at: now,
        expires_at: now + 60,
        nonce: nonce.into(),
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign_request(key, &mut r);
    r
}
fn sign_request(key: &SigningKey, request: &mut ManagementRequest) {
    request.signature.clear();
    let mut v = serde_json::to_value(&*request).unwrap();
    v.as_object_mut().unwrap().remove("signature");
    request.signature = STANDARD.encode(key.sign(&serde_jcs::to_vec(&v).unwrap()).to_bytes());
}
fn policy(now: u64) -> ControllerPolicy {
    ControllerPolicy {
        audience: "controller:test".into(),
        domain: "domain:test".into(),
        allowed_actions: BTreeSet::from(["apply".into()]),
        revocation_checkpoint: now,
        max_checkpoint_age: 100,
        high_impact_actions: BTreeSet::from(["apply".into()]),
        max_decision_events: 100,
    }
}

#[test]
fn controller_persists_explicit_lifecycle_outcomes_and_bounds_history() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("state.db");
    let k = SigningKey::from_bytes(&[11; 32]);
    let now = 4_000;
    let mut bounded = policy(now);
    bounded.max_decision_events = 2;
    let mut c = Controller::open(&p, bounded.clone(), k.verifying_key().to_bytes()).unwrap();
    let r = request(&k, "outcome", 0, now);
    c.evaluate(&r, now).unwrap();
    c.record_outcome(
        &r.request_id,
        DecisionState::Deferred,
        "WAITING",
        1,
        now + 1,
    )
    .unwrap();
    c.record_outcome(
        &r.request_id,
        DecisionState::Partial,
        "PARTIAL_APPLY",
        1,
        now + 2,
    )
    .unwrap();
    assert_eq!(c.decision_history(&r.request_id).unwrap().len(), 2);
    drop(c);
    let c = Controller::open(&p, bounded, k.verifying_key().to_bytes()).unwrap();
    let history = c.decision_history(&r.request_id).unwrap();
    assert_eq!(history.last().unwrap().decision, DecisionState::Partial);
    assert!(matches!(
        c.record_outcome(&r.request_id, DecisionState::Accepted, "NO", 1, now + 3),
        Err(ControllerError::Invalid("outcome"))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn controller_replay_restart_and_binding() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("state.db");
    let k = SigningKey::from_bytes(&[7; 32]);
    let now = 1000;
    let mut c = Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();
    let r = request(&k, "one", 0, now);
    assert_eq!(c.evaluate(&r, now).unwrap().generation, 1);
    assert!(matches!(c.evaluate(&r, now), Err(ControllerError::Replay)));
    drop(c);
    let mut c = Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();
    assert_eq!(c.generation().unwrap(), 1);
    let mut wrong = request(&k, "two", 1, now);
    wrong.audience = "wrong".into();
    assert!(matches!(
        c.evaluate(&wrong, now),
        Err(ControllerError::Policy)
    ));
    let rejected = c.decision_history(&wrong.request_id).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].decision, DecisionState::Rejected);
    assert_eq!(rejected[0].generation, 1);
    drop(c);
    let c = Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        c.decision_history(&r.request_id).unwrap()[0].decision,
        DecisionState::Accepted
    );
    assert_eq!(
        c.decision_history(&wrong.request_id).unwrap()[0].decision,
        DecisionState::Rejected
    );
}

#[test]
fn controller_rejects_tamper_stale_revocation_and_unbounded_input() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("state.db");
    let k = SigningKey::from_bytes(&[8; 32]);
    let now = 2000;
    let mut c = Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();

    let mut tampered = request(&k, "tampered", 0, now);
    tampered.plan_digest = "sha256:altered".into();
    assert!(matches!(
        c.evaluate(&tampered, now),
        Err(ControllerError::Signature)
    ));
    assert_eq!(
        c.decision_history(&tampered.request_id).unwrap()[0].decision,
        DecisionState::Rejected
    );

    let mut stale_policy = policy(now);
    stale_policy.revocation_checkpoint = 1;
    let mut stale = Controller::open(
        &d.path().join("stale.db"),
        stale_policy,
        k.verifying_key().to_bytes(),
    )
    .unwrap();
    let stale_request = request(&k, "stale", 0, now);
    assert!(matches!(
        stale.evaluate(&stale_request, now),
        Err(ControllerError::Policy)
    ));

    let mut oversized = request(&k, "bounded", 0, now);
    oversized.issuer_id = "x".repeat(129);
    assert!(matches!(
        c.evaluate(&oversized, now),
        Err(ControllerError::Invalid("bounded_text"))
    ));
}

#[test]
fn concurrent_generation_has_one_winner_without_widening_authority() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("state.db");
    let k = SigningKey::from_bytes(&[9; 32]);
    let now = 3000;
    Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for nonce in ["parallel-a", "parallel-b"] {
        let path = p.clone();
        let barrier = barrier.clone();
        let key = k.clone();
        handles.push(thread::spawn(move || {
            let mut controller =
                Controller::open(&path, policy(now), key.verifying_key().to_bytes()).unwrap();
            let signed = request(&key, nonce, 0, now);
            barrier.wait();
            controller.evaluate(&signed, now)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ControllerError::Generation)))
            .count(),
        1
    );
    let controller = Controller::open(&p, policy(now), k.verifying_key().to_bytes()).unwrap();
    assert_eq!(controller.generation().unwrap(), 1);
}

#[cfg(unix)]
#[test]
fn headless_controller_transcript_is_owner_only_and_restart_safe() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::{fs::PermissionsExt, net::UnixStream};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    let d = tempfile::tempdir().unwrap();
    let socket = d.path().join("controller.sock");
    let db = d.path().join("controller.db");
    let public_key = d.path().join("controller.pub");
    let key = SigningKey::from_bytes(&[10; 32]);
    std::fs::write(&public_key, key.verifying_key().to_bytes()).unwrap();
    let now = Controller::now();
    let direct_apply = request(&key, "legacy-apply", 0, now);
    let mut signed = request(&key, "cli-transcript", 0, now);
    signed.action = "observe".into();
    sign_request(&key, &mut signed);

    let start = || {
        Command::new(env!("CARGO_BIN_EXE_iicp-management-controller"))
            .args([
                "serve",
                socket.to_str().unwrap(),
                db.to_str().unwrap(),
                public_key.to_str().unwrap(),
                "controller:test",
                "domain:test",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let transact = |request: &ManagementRequest| {
        let mut stream = UnixStream::connect(&socket).unwrap();
        writeln!(stream, "{}", serde_json::to_string(request).unwrap()).unwrap();
        let mut response = String::new();
        BufReader::new(stream).read_line(&mut response).unwrap();
        serde_json::from_str::<serde_json::Value>(&response).unwrap()
    };

    let mut child = start();
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists());
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let direct = transact(&direct_apply);
    assert_eq!(direct["decision"], "rejected");
    assert_eq!(direct["reason"], "REQUEST_APPLY_GATE_REQUIRED");
    assert_eq!(transact(&signed)["decision"], "accepted");
    child.kill().unwrap();
    child.wait().unwrap();

    let mut restarted = start();
    thread::sleep(Duration::from_millis(100));
    assert!(socket.exists());
    let replay = transact(&signed);
    assert_eq!(replay["decision"], "rejected");
    assert_eq!(replay["reason"], "REQUEST_REPLAY");
    restarted.kill().unwrap();
    restarted.wait().unwrap();
}
fn op(id: &str, g: u64, v: serde_json::Value) -> AdapterOperation {
    AdapterOperation {
        operation_id: id.into(),
        target_id: "target".into(),
        action: "apply".into(),
        plan_digest: "p".into(),
        desired_digest: digest(&v).unwrap(),
        expected_generation: g,
        expires_at: 2000,
        capability: "synthetic-v1".into(),
        desired: v,
        related_operation_id: None,
    }
}
fn authorized(mut operation: AdapterOperation, now: u64) -> AuthorizedAdapterOperation {
    operation.expires_at = operation.expires_at.min(now + 60);
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[44; 32]);
    let mut controller_policy = policy(now);
    controller_policy.allowed_actions =
        BTreeSet::from([operation.action.clone(), "observe".into()]);
    controller_policy.high_impact_actions = controller_policy.allowed_actions.clone();
    let mut controller = Controller::open(
        &directory.path().join("controller.db"),
        controller_policy,
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    for generation in 0..operation.expected_generation {
        let mut seed = request(&key, &format!("seed:{generation}"), generation, now);
        seed.action = "observe".into();
        seed.request_id = format!("seed:{generation}");
        seed.nonce = format!("seed-nonce:{generation}");
        sign_request(&key, &mut seed);
        controller.evaluate(&seed, now).unwrap();
    }
    let mut management_request = request(
        &key,
        &operation.operation_id,
        operation.expected_generation,
        now,
    );
    management_request.request_id = operation.operation_id.clone();
    management_request.action = operation.action.clone();
    management_request.resource_ids = vec![operation.target_id.clone()];
    management_request.payload_digest = operation.desired_digest.clone();
    management_request.plan_digest = operation.plan_digest.clone();
    management_request.expires_at = operation.expires_at;
    sign_request(&key, &mut management_request);
    controller
        .authorize_adapter_operation(&management_request, operation, now)
        .unwrap()
        .1
}
#[test]
fn synthetic_is_idempotent_and_reversible() {
    let mut a = SyntheticAdapter::new();
    let o = op("one", 0, json!({"v":1}));
    let first = a.apply(&o, 1000).unwrap();
    assert_eq!(
        a.apply(&o, 1000).unwrap().result_digest,
        first.result_digest
    );
    let mut changed = o.clone();
    changed.desired = json!({"v":2});
    changed.desired_digest = digest(&changed.desired).unwrap();
    assert_eq!(
        a.apply(&changed, 1000).unwrap_err(),
        AdapterError::ReplayConflict
    );
    let mut rollback = op("rollback-one", 1, Value::Null);
    rollback.action = "rollback".into();
    rollback.related_operation_id = Some("one".into());
    let first_rollback = a.rollback(&rollback).unwrap();
    assert_eq!(a.rollback(&rollback).unwrap(), first_rollback);
    assert_eq!(a.observe().unwrap(), serde_json::Value::Null)
}

#[test]
fn synthetic_reports_drift_partial_and_irrecoverable_states() {
    let mut adapter = SyntheticAdapter::new();
    let applied = op("base", 0, json!({"v": 1}));
    adapter.apply(&applied, 1000).unwrap();
    let mut drift = op("drift", 1, json!({"v": 2}));
    drift.action = "verify".into();
    assert_eq!(
        adapter.verify(&drift).unwrap().state,
        ConvergenceState::Failed
    );

    let partial = op("partial", 1, json!({"simulate": "partial"}));
    let partial_receipt = adapter.apply(&partial, 1000).unwrap();
    assert_eq!(partial_receipt.state, ConvergenceState::PartiallyConverged);
    assert_eq!(adapter.apply(&partial, 1000).unwrap(), partial_receipt);

    let failed = op(
        "irrecoverable",
        2,
        json!({"simulate": "irrecoverable_failure"}),
    );
    let failed_receipt = adapter.apply(&failed, 1000).unwrap();
    assert_eq!(failed_receipt.state, ConvergenceState::Failed);
    assert_eq!(adapter.apply(&failed, 1000).unwrap(), failed_receipt);
}

#[test]
fn adapter_host_is_target_scoped_cancellable_and_dry_run_safe() {
    let mut host = AdapterHost::new();
    host.register("target", "synthetic-v1", Box::new(SyntheticAdapter::new()));
    let mut dry = op("dry", 0, json!({"v": 1}));
    dry.action = "dry_run".into();
    let dry = authorized(dry, 1000);
    let dry_receipt = host.execute(&dry, 1000).unwrap();
    assert_eq!(dry_receipt.reason, "DRY_RUN_VALID");
    assert_eq!(host.execute(&dry, 1000).unwrap(), dry_receipt);
    let mut altered_dry = dry.operation().clone();
    altered_dry.plan_digest = "another-plan".into();
    let altered_dry = authorized(altered_dry, 1000);
    assert_eq!(
        host.execute(&altered_dry, 1000).unwrap_err(),
        AdapterError::ReplayConflict
    );

    let mut unknown = dry.operation().clone();
    unknown.operation_id = "unknown".into();
    unknown.target_id = "foreign".into();
    let unknown = authorized(unknown, 1000);
    assert_eq!(
        host.execute(&unknown, 1000).unwrap_err(),
        AdapterError::UnknownTarget
    );

    let apply = op("cancelled", 0, json!({"v": 2}));
    host.cancel(&apply.operation_id);
    let apply = authorized(apply, 1000);
    assert_eq!(
        host.execute(&apply, 1000).unwrap_err(),
        AdapterError::Cancelled
    );

    let mut expired = op("expired", 0, json!({"v": 3}));
    expired.expires_at = 999;
    let expired = authorized(expired, 998);
    assert_eq!(
        host.execute(&expired, 1000).unwrap_err(),
        AdapterError::Invalid
    );
}

#[test]
fn adapter_inspection_is_deterministic_bounded_and_non_authorizing() {
    let mut host = AdapterHost::new();
    host.register(
        "target:b",
        "synthetic-v1",
        Box::new(SyntheticAdapter::new()),
    );
    host.register(
        "target:a",
        "synthetic-v1",
        Box::new(SyntheticAdapter::new()),
    );
    let before = host.inspection(1000, 60);
    assert!(!before.authorizes_mutation);
    assert_eq!(before.entries[0].target_id, "target:a");
    assert_eq!(before.entries[1].target_id, "target:b");
    assert!(before
        .entries
        .iter()
        .all(|entry| entry.observed_generation.is_none()));

    let mut applied = op("observed", 0, json!({"v": 1}));
    applied.target_id = "target:b".into();
    let applied = authorized(applied, 1000);
    host.execute(&applied, 1000).unwrap();
    let after = host.inspection(1001, 60);
    assert_eq!(after.entries[0], before.entries[0]);
    assert_eq!(after.entries[1].observed_generation, Some(1));
    assert_eq!(
        after.entries[1].convergence_state,
        Some(ConvergenceState::Converged)
    );
    validate_adapter_inspection(&after, &BTreeSet::new(), 1001, 0).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("inspection.db");
    let key = SigningKey::from_bytes(&[31; 32]);
    let controller =
        Controller::open(&database, policy(1001), key.verifying_key().to_bytes()).unwrap();
    drop(controller);
    let snapshot = inspect_controller_database(&database, 10).unwrap();
    let combined = attach_adapter_inspection(snapshot, after, 1001).unwrap();
    assert_eq!(
        combined.observed_state,
        "observed_without_convergence_receipt"
    );
}

#[test]
fn adapter_inspection_conformance_fixture_matches_rust_validator() {
    let path = format!(
        "{}/fixtures/adapter-inspection-conformance-v1.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let schema_path = format!(
        "{}/contracts/adapter-inspection-v1.schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let schema: Value = serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();
    let schema = jsonschema::validator_for(&schema).unwrap();
    let now = fixture["now"].as_u64().unwrap();
    let skew = fixture["clock_skew"].as_u64().unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input: AdapterInspectionV1 = serde_json::from_value(case["input"].clone()).unwrap();
        let actual = validate_adapter_inspection(&input, &BTreeSet::new(), now, skew).is_ok();
        assert_eq!(actual, case["expected"] == "accept", "{}", case["id"]);
        if case["id"] == "AI1-VALID-CONVERGED" {
            assert!(schema.is_valid(&case["input"]));
        }
    }
}

#[test]
fn adapter_inspection_rejects_oversized_and_secret_shaped_evidence() {
    let mut host = AdapterHost::new();
    host.register("target", "synthetic-v1", Box::new(SyntheticAdapter::new()));
    let mut inspection = host.inspection(1000, 60);
    inspection.entries = vec![inspection.entries[0].clone(); 1025];
    assert_eq!(
        validate_adapter_inspection(&inspection, &BTreeSet::new(), 1000, 0),
        Err(AdapterError::Invalid)
    );

    let mut value = serde_json::to_value(host.inspection(1000, 60)).unwrap();
    value["entries"][0]["raw_configuration"] = json!({"token":"forbidden"});
    assert!(serde_json::from_value::<AdapterInspectionV1>(value).is_err());
}

#[test]
fn operation_replay_binds_plan_target_and_capability() {
    let mut adapter = SyntheticAdapter::new();
    let original = op("bound", 0, json!({"v": 1}));
    adapter.apply(&original, 1000).unwrap();
    let mut altered = original.clone();
    altered.plan_digest = "different-plan".into();
    assert_eq!(
        adapter.apply(&altered, 1000).unwrap_err(),
        AdapterError::ReplayConflict
    );
}

#[test]
fn adapter_generation_precondition_rejects_concurrent_modification() {
    let mut adapter = SyntheticAdapter::new();
    let winner = op("winner", 0, json!({"v": 1}));
    let stale = op("stale", 0, json!({"v": 2}));
    adapter.apply(&winner, 1000).unwrap();
    assert_eq!(
        adapter.apply(&stale, 1000).unwrap_err(),
        AdapterError::Generation
    );
    assert_eq!(adapter.observe().unwrap(), json!({"v": 1}));
}

#[test]
fn adapter_host_rejects_unknown_action_and_capability_and_routes_rollback() {
    let mut host = AdapterHost::new();
    host.register("target", "synthetic-v1", Box::new(SyntheticAdapter::new()));
    let applied = op("applied", 0, json!({"v": 1}));
    let applied = authorized(applied, 1000);
    assert_eq!(host.execute(&applied, 1000).unwrap().reason, "APPLIED");

    let mut bad_action = op("bad-action", 1, json!({"v": 2}));
    bad_action.action = "shell".into();
    let bad_action = authorized(bad_action, 1000);
    assert_eq!(
        host.execute(&bad_action, 1000).unwrap_err(),
        AdapterError::Unsupported
    );

    let mut bad_capability = op("bad-cap", 1, json!({"v": 2}));
    bad_capability.capability = "shell-v1".into();
    let bad_capability = authorized(bad_capability, 1000);
    assert_eq!(
        host.execute(&bad_capability, 1000).unwrap_err(),
        AdapterError::UnknownTarget
    );

    let mut rollback = op("rollback", 1, Value::Null);
    rollback.action = "rollback".into();
    rollback.related_operation_id = Some("applied".into());
    let rollback = authorized(rollback, 1000);
    assert_eq!(host.execute(&rollback, 1000).unwrap().reason, "ROLLED_BACK");
}

#[test]
fn adapter_descriptor_declares_narrow_outbound_permissions() {
    let descriptor = SyntheticAdapter::new().descriptor();
    assert!(descriptor.outbound_only);
    assert!(!descriptor.resolves_secret_references);
    assert!(!descriptor.actions.iter().any(|action| action == "shell"));
}

#[test]
fn controller_binds_adapter_target_plan_action_and_desired_state() {
    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[45; 32]);
    let now = 1000;
    let mut controller = Controller::open(
        &directory.path().join("controller.db"),
        policy(now),
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    let operation = op("bound-request", 0, json!({"v": 1}));
    let mut management_request = request(&key, "bound-request", 0, now);
    management_request.resource_ids = vec!["another-target".into()];
    management_request.payload_digest = operation.desired_digest.clone();
    management_request.plan_digest = operation.plan_digest.clone();
    management_request.expires_at = operation.expires_at;
    sign_request(&key, &mut management_request);
    assert!(matches!(
        controller.authorize_adapter_operation(&management_request, operation, now),
        Err(ControllerError::AdapterBinding)
    ));
    assert_eq!(controller.generation().unwrap(), 0);
}
#[test]
fn runtime_config_atomic_secret_safe_and_rollback() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("runtime.json");
    let initial = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    std::fs::write(&p, serde_json::to_vec(&initial).unwrap()).unwrap();
    let mut desired_config = initial.clone();
    desired_config.secret_refs.insert(
        "membership".into(),
        SecretRef::Environment {
            name: "IICP_MEMBERSHIP".into(),
        },
    );
    let desired = serde_json::to_value(&desired_config).unwrap();
    let mut a = RuntimeConfigAdapter::open(&p).unwrap();
    let mut o = op("cfg", 0, desired.clone());
    o.capability = "runtime-config-v1".into();
    a.apply(&o, 1000).unwrap();
    assert_eq!(a.observe().unwrap(), desired);
    drop(a);
    let mut a = RuntimeConfigAdapter::open(&p).unwrap();
    assert_eq!(a.apply(&o, 1000).unwrap().reason, "APPLIED");

    let mut unsafe_value = serde_json::to_value(&initial).unwrap();
    unsafe_value["password"] = json!("x");
    let mut unsafe_o = op("unsafe", 1, unsafe_value);
    unsafe_o.capability = "runtime-config-v1".into();
    assert_eq!(a.apply(&unsafe_o, 1000).unwrap_err(), AdapterError::Invalid);
    let mut invalid_local = serde_json::to_value(&initial).unwrap();
    invalid_local["network"]["allow_public_fallback"] = json!(true);
    let mut invalid_local_operation = op("invalid-local", 1, invalid_local);
    invalid_local_operation.capability = "runtime-config-v1".into();
    assert_eq!(
        a.apply(&invalid_local_operation, 1000).unwrap_err(),
        AdapterError::Invalid
    );
    let mut rollback = op("rollback-cfg", 1, Value::Null);
    rollback.action = "rollback".into();
    rollback.capability = "runtime-config-v1".into();
    rollback.related_operation_id = Some("cfg".into());
    let first_rollback = a.rollback(&rollback).unwrap();
    assert_eq!(a.rollback(&rollback).unwrap(), first_rollback);
    assert_eq!(a.observe().unwrap()["mode"], "local_only");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(p.with_extension("iicp-management-state.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn runtime_config_interruption_and_readback_failures_are_truthful() {
    let d = tempfile::tempdir().unwrap();
    let initial = RuntimeConfigV1::preset(OperatingMode::LocalOnly);
    let initial_value = serde_json::to_value(&initial).unwrap();
    let mut desired_config = initial.clone();
    desired_config.secret_refs.insert(
        "test".into(),
        SecretRef::Environment {
            name: "IICP_TEST_REF".into(),
        },
    );
    let desired = serde_json::to_value(&desired_config).unwrap();

    let interrupted_path = d.path().join("interrupted.json");
    std::fs::write(&interrupted_path, serde_json::to_vec(&initial).unwrap()).unwrap();
    let mut operation = op("interrupted", 0, desired.clone());
    operation.capability = "runtime-config-v1".into();
    let mut interrupted = RuntimeConfigAdapter::open(&interrupted_path)
        .unwrap()
        .with_failure_injection(RuntimeConfigFailureInjection {
            interrupt_before_replace: true,
            ..Default::default()
        });
    assert_eq!(
        interrupted.apply(&operation, 1000).unwrap_err(),
        AdapterError::Io
    );
    assert_eq!(interrupted.observe().unwrap(), initial_value);
    assert_eq!(
        std::fs::read_dir(d.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".iicp-stage-"))
            .count(),
        0
    );

    let recovered_path = d.path().join("recovered.json");
    std::fs::write(&recovered_path, serde_json::to_vec(&initial).unwrap()).unwrap();
    let mut recovered_operation = op("recovered", 0, desired.clone());
    recovered_operation.capability = "runtime-config-v1".into();
    let mut recovered = RuntimeConfigAdapter::open(&recovered_path)
        .unwrap()
        .with_failure_injection(RuntimeConfigFailureInjection {
            readback_mismatch: true,
            ..Default::default()
        });
    let recovered_receipt = recovered.apply(&recovered_operation, 1000).unwrap();
    assert_eq!(recovered_receipt.state, ConvergenceState::Failed);
    assert_eq!(recovered_receipt.reason, "READBACK_MISMATCH_ROLLED_BACK");
    assert_eq!(recovered.observe().unwrap(), initial_value);

    let partial_path = d.path().join("partial.json");
    std::fs::write(&partial_path, serde_json::to_vec(&initial).unwrap()).unwrap();
    let mut partial_operation = op("partial", 0, desired);
    partial_operation.capability = "runtime-config-v1".into();
    let mut partial = RuntimeConfigAdapter::open(&partial_path)
        .unwrap()
        .with_failure_injection(RuntimeConfigFailureInjection {
            readback_mismatch: true,
            rollback_failure: true,
            ..Default::default()
        });
    let receipt = partial.apply(&partial_operation, 1000).unwrap();
    assert_eq!(receipt.state, ConvergenceState::PartiallyConverged);
    assert_eq!(receipt.reason, "READBACK_MISMATCH_ROLLBACK_FAILED");
}

#[test]
fn runtime_config_never_persists_unsafe_existing_rollback_material() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("unsafe-existing.json");
    std::fs::write(&path, br#"{"schema_version":1,"password":"legacy"}"#).unwrap();
    let desired = serde_json::to_value(RuntimeConfigV1::preset(OperatingMode::LocalOnly)).unwrap();
    let mut operation = op("unsafe-existing", 0, desired);
    operation.capability = "runtime-config-v1".into();
    let mut adapter = RuntimeConfigAdapter::open(&path).unwrap();
    assert_eq!(
        adapter.apply(&operation, 1000).unwrap_err(),
        AdapterError::Invalid
    );
    assert!(!path.with_extension("iicp-management-state.json").exists());
}
