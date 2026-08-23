use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::{adapters::*, controller::*, digest};
use serde_json::json;
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
    let mut v = serde_json::to_value(&r).unwrap();
    v.as_object_mut().unwrap().remove("signature");
    r.signature = STANDARD.encode(key.sign(&serde_jcs::to_vec(&v).unwrap()).to_bytes());
    r
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
    let signed = request(&key, "cli-transcript", 0, now);

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
    }
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
    a.rollback("one").unwrap();
    assert_eq!(a.observe().unwrap(), serde_json::Value::Null)
}
#[test]
fn runtime_config_atomic_secret_safe_and_rollback() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("runtime.json");
    std::fs::write(&p, r#"{"schema_version":"1","mode":"local_only"}"#).unwrap();
    let mut a = RuntimeConfigAdapter::new(&p);
    let desired = json!({"schema_version":"1","mode":"local_only","secret_refs":{"membership":"keychain://test"}});
    let o = op("cfg", 0, desired.clone());
    a.apply(&o, 1000).unwrap();
    assert_eq!(a.observe().unwrap(), desired);
    let unsafe_o = op("unsafe", 1, json!({"schema_version":"1","password":"x"}));
    assert_eq!(a.apply(&unsafe_o, 1000).unwrap_err(), AdapterError::Invalid);
    a.rollback("cfg").unwrap();
    assert_eq!(a.observe().unwrap()["mode"], "local_only")
}
