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
