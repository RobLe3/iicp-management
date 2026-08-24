use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use iicp_management_core::controller::{
    Controller, ControllerError, ControllerPolicy, ManagementRequest, SIGNATURE_PROFILE,
};
use iicp_management_core::policy_lifecycle::*;
use iicp_management_core::{
    digest, plan, AcceptedState, DesiredStateBundle, ExtensionClass, ExtensionRequirement,
    PolicyDecision,
};
use jsonschema::validator_for;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn revision(id: &str, policy: Value) -> PolicyRevisionV1 {
    PolicyRevisionV1 {
        schema_version: "1".into(),
        policy_id: id.into(),
        revision_id: "r1".into(),
        authority: "domain:test".into(),
        scope: "application:test".into(),
        disposition: PolicyDisposition::Stored,
        policy,
        valid_from: Some(100),
        valid_until: Some(200),
        extensions: vec![],
    }
}

fn reference(id: &str, rank: u32, mandatory: bool, order: u32) -> PolicyReferenceV1 {
    PolicyReferenceV1 {
        policy_id: id.into(),
        revision_id: "r1".into(),
        authority_rank: rank,
        mandatory,
        order,
    }
}

fn binding(policies: Vec<PolicyReferenceV1>) -> ApplicationBindingV1 {
    ApplicationBindingV1 {
        schema_version: "1".into(),
        binding_id: "binding:finance".into(),
        application_id: "application:finance".into(),
        authority: "domain:test".into(),
        policies,
        policy_sets: vec![],
        valid_from: Some(100),
        valid_until: Some(200),
        extensions: vec![],
    }
}

#[test]
fn lifecycle_schema_accepts_every_public_projection() {
    let schema: Value =
        serde_json::from_str(include_str!("../contracts/policy-lifecycle-v1.schema.json")).unwrap();
    let validator = validator_for(&schema).unwrap();
    let policy = revision("policy:baseline", json!({"eq": ["member", true]}));
    assert!(validator.is_valid(&serde_json::to_value(&policy).unwrap()));
    let app = binding(vec![reference("policy:baseline", 100, true, 1)]);
    assert!(validator.is_valid(&serde_json::to_value(&app).unwrap()));
}

#[test]
fn immutable_revision_id_cannot_be_reused_for_other_content() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:baseline", json!({"eq": ["member", true]})))
        .unwrap();
    assert_eq!(
        repository.store_revision(revision(
            "policy:baseline",
            json!({"eq": ["member", false]})
        )),
        Err(PolicyLifecycleError::DigestMismatch)
    );
}

#[test]
fn binding_rejects_missing_revision_and_duplicate_order() {
    let mut repository = InMemoryPolicyRepository::default();
    assert_eq!(
        repository.store_binding(binding(vec![reference("policy:missing", 100, true, 1)])),
        Err(PolicyLifecycleError::RevisionNotFound)
    );
    let duplicate = binding(vec![
        reference("policy:a", 100, true, 1),
        reference("policy:b", 50, false, 1),
    ]);
    assert_eq!(
        validate_application_binding(&duplicate),
        Err(PolicyLifecycleError::DuplicateMember)
    );
}

#[test]
fn activation_is_digest_and_generation_bound() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:baseline", json!({"eq": ["member", true]})))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:baseline", 100, true, 1)]))
        .unwrap();
    let activation = repository
        .activation_for_binding("binding:finance", "domain:test", 110, Some(190))
        .unwrap();
    repository.activate(activation.clone()).unwrap();
    assert_eq!(
        repository.activate(activation),
        Err(PolicyLifecycleError::StaleGeneration)
    );
    assert_eq!(
        repository
            .active("binding:finance")
            .unwrap()
            .target_generation,
        1
    );
}

#[test]
fn activation_rejects_expired_or_invalid_policy() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:expired", json!({"eq": ["member", true]})))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:expired", 100, true, 1)]))
        .unwrap();
    assert_eq!(
        repository.activation_for_binding("binding:finance", "domain:test", 250, None),
        Err(PolicyLifecycleError::InvalidActivation)
    );

    let mut invalid_repository = InMemoryPolicyRepository::default();
    let mut invalid = revision("policy:invalid", json!({"eq": ["member", true]}));
    invalid.disposition = PolicyDisposition::Invalid;
    invalid_repository.store_revision(invalid).unwrap();
    invalid_repository
        .store_binding(binding(vec![reference("policy:invalid", 100, true, 1)]))
        .unwrap();
    assert_eq!(
        invalid_repository.activation_for_binding("binding:finance", "domain:test", 150, None),
        Err(PolicyLifecycleError::InvalidActivation)
    );
}

#[test]
fn explicit_deny_wins_and_sources_are_deterministic() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:allow", json!({"eq": ["member", true]})))
        .unwrap();
    repository
        .store_revision(revision("policy:deny", json!({"eq": ["region", "EU"]})))
        .unwrap();
    repository
        .store_binding(binding(vec![
            reference("policy:allow", 10, false, 2),
            reference("policy:deny", 100, true, 1),
        ]))
        .unwrap();
    let effective = repository
        .effective_policy("binding:finance", &json!({"member": true, "region": "US"}))
        .unwrap();
    assert_eq!(effective.decision, PolicyDecision::Deny);
    assert_eq!(effective.sources[0].policy_id, "policy:deny");
    assert_eq!(effective.reason_codes[0], "IICP-POLICY-EFFECTIVE-DENY");
}

#[test]
fn mandatory_unknown_is_indeterminate_not_allow() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision(
            "policy:evidence",
            json!({"contains": ["effective_capabilities", "input.text"]}),
        ))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:evidence", 100, true, 1)]))
        .unwrap();
    let effective = repository
        .effective_policy("binding:finance", &json!({"effective_capabilities": null}))
        .unwrap();
    assert_eq!(effective.decision, PolicyDecision::Indeterminate);
}

#[test]
fn simulation_reports_new_allow_without_mutation() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision(
            "policy:membership",
            json!({"eq": ["member", true]}),
        ))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:membership", 100, true, 1)]))
        .unwrap();
    let current = repository
        .effective_policy("binding:finance", &json!({"member": false}))
        .unwrap();
    let proposed = repository
        .effective_policy("binding:finance", &json!({"member": true}))
        .unwrap();
    let simulation = simulate_policy_change(current, proposed);
    assert!(simulation.decision_changed);
    assert!(simulation.newly_allowed);
    assert!(!simulation.newly_denied);
    assert!(repository.active("binding:finance").is_none());
}

#[test]
fn lifecycle_resource_uses_existing_exact_plan_binding() {
    let policy = revision("policy:baseline", json!({"eq": ["member", true]}));
    let resource = lifecycle_resource("policy:baseline@r1", POLICY_REVISION_KIND, &policy).unwrap();
    let bundle = DesiredStateBundle {
        schema_version: "1".into(),
        bundle_id: "bundle:policy-1".into(),
        issuer: "did:iicp:admin:test".into(),
        audience: "domain:test".into(),
        expected_generation: 0,
        resources: vec![resource],
        extensions: vec![],
    };
    let planned = plan(
        &bundle,
        &AcceptedState {
            generation: 0,
            resource_digests: BTreeMap::new(),
        },
        &BTreeSet::new(),
        4,
    )
    .unwrap();
    assert_eq!(planned.operations[0].after_digest, digest(&policy).unwrap());
    assert_eq!(planned.operations[0].target_generation, 1);
}

#[test]
fn required_unknown_extension_remains_visible_to_existing_planner_gate() {
    let mut policy = revision("policy:baseline", json!({"eq": ["member", true]}));
    policy.extensions.push(ExtensionRequirement {
        id: "urn:iicp:management:policy:future-required:v1".into(),
        class: ExtensionClass::RequiredSecurityCritical,
    });
    let mut repository = InMemoryPolicyRepository::default();
    assert!(matches!(
        repository.store_revision(policy.clone()),
        Err(PolicyLifecycleError::UnsupportedRequiredExtension(_))
    ));
    let resource = lifecycle_resource("policy:baseline@r1", POLICY_REVISION_KIND, &policy).unwrap();
    let bundle = DesiredStateBundle {
        schema_version: "1".into(),
        bundle_id: "bundle:policy-2".into(),
        issuer: "did:iicp:admin:test".into(),
        audience: "domain:test".into(),
        expected_generation: 0,
        resources: vec![resource],
        extensions: policy.extensions,
    };
    assert!(plan(
        &bundle,
        &AcceptedState {
            generation: 0,
            resource_digests: BTreeMap::new(),
        },
        &BTreeSet::new(),
        4
    )
    .is_err());
}

#[test]
fn inventory_brief_resolution_and_explanation_share_effective_state() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:baseline", json!({"eq": ["member", true]})))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:baseline", 100, true, 1)]))
        .unwrap();
    let activation = repository
        .activation_for_binding("binding:finance", "domain:test", 110, Some(190))
        .unwrap();
    repository.activate(activation).unwrap();

    let inventory = repository.policy_inventory(true).unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.entries[0].active_binding_count, 1);
    assert_eq!(inventory.entries[0].disposition, PolicyDisposition::Active);

    let facts = json!({"member": true});
    let brief = repository
        .application_policy_brief("binding:finance", &facts)
        .unwrap();
    assert_eq!(brief.active_generation, Some(1));
    let summary = repository
        .resolution_summary(
            "binding:finance",
            "urn:iicp:intent:rules:evaluate:v1",
            &facts,
            vec!["local".into()],
        )
        .unwrap();
    assert!(summary.eligible);
    let explanation = repository
        .explain_decision(
            "decision:1",
            "urn:iicp:intent:rules:evaluate:v1",
            &brief.effective_policy,
        )
        .unwrap();
    assert_eq!(explanation.decision, PolicyDecision::Allow);
    assert_eq!(explanation.determining_policy_ids, vec!["policy:baseline"]);
}

fn signed_policy_request(
    key: &SigningKey,
    activation: &PolicyActivationV1,
    plan_digest: &str,
    nonce: &str,
    now: u64,
) -> ManagementRequest {
    let mut request = ManagementRequest {
        schema_version: "1".into(),
        request_id: format!("request:{nonce}"),
        issuer_id: "did:iicp:admin:test".into(),
        audience: "controller:test".into(),
        administrative_domain: "domain:test".into(),
        action: "apply_policy".into(),
        resource_ids: vec![activation.binding_id.clone()],
        payload_digest: digest(activation).unwrap(),
        plan_digest: plan_digest.into(),
        expected_generation: activation.expected_generation,
        issued_at: now,
        expires_at: now + 60,
        nonce: nonce.into(),
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    let mut value = serde_json::to_value(&request).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    request.signature = STANDARD.encode(key.sign(&serde_jcs::to_vec(&value).unwrap()).to_bytes());
    request
}

#[test]
fn domain_controller_authorizes_exact_policy_activation_once() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(revision("policy:baseline", json!({"eq": ["member", true]})))
        .unwrap();
    repository
        .store_binding(binding(vec![reference("policy:baseline", 100, true, 1)]))
        .unwrap();
    let activation = repository
        .activation_for_binding("binding:finance", "domain:test", 150, Some(190))
        .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[29; 32]);
    let policy = ControllerPolicy {
        audience: "controller:test".into(),
        domain: "domain:test".into(),
        allowed_actions: BTreeSet::from(["apply_policy".into()]),
        revocation_checkpoint: 150,
        max_checkpoint_age: 60,
        high_impact_actions: BTreeSet::from(["apply_policy".into()]),
        max_decision_events: 16,
    };
    let mut controller = Controller::open(
        &directory.path().join("controller.db"),
        policy,
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    let request = signed_policy_request(&key, &activation, "sha256:policy-plan", "one", 150);
    assert_eq!(controller.evaluate(&request, 150).unwrap().generation, 1);
    repository.activate(activation).unwrap();
    assert!(matches!(
        controller.evaluate(&request, 150),
        Err(ControllerError::Replay)
    ));
}
