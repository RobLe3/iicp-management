use iicp_management_core::policy_lifecycle::{
    ApplicationBindingV1, InMemoryPolicyRepository, PolicyDisposition, PolicyReferenceV1,
    PolicyRepository, PolicyRevisionV1,
};
use iicp_management_core::progressive_authority::*;
use iicp_management_core::{ExtensionClass, ExtensionRequirement, PolicyDecision};
use jsonschema::validator_for;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn evidence(mode: OperatingMode) -> ProgressiveAuthorityEvidenceV1 {
    ProgressiveAuthorityEvidenceV1 {
        schema_version: "1".into(),
        evidence_id: "evidence:test".into(),
        mode,
        application_id: "application:finance".into(),
        intent: "urn:iicp:intent:test:v1".into(),
        policy_generation: 4,
        fact_snapshot_digest: digest('a'),
        observed_at: 100,
        actual_decision: Some(PolicyDecision::Deny),
        proposed_decision: None,
        plan_digest: None,
        authorization_evidence_digest: None,
        policy_boundary: PolicyBoundaryAssessment::Indeterminate,
        may_request_apply: false,
        extensions: vec![],
    }
}

#[test]
fn schema_accepts_all_four_mode_shapes() {
    let schema: Value = serde_json::from_str(include_str!(
        "../contracts/progressive-authority-v1.schema.json"
    ))
    .unwrap();
    let validator = validator_for(&schema).unwrap();
    let observe = evidence(OperatingMode::Observe);
    let mut recommend = evidence(OperatingMode::Recommend);
    recommend.proposed_decision = Some(PolicyDecision::Allow);
    let mut confirm = evidence(OperatingMode::Confirm);
    confirm.actual_decision = None;
    confirm.proposed_decision = Some(PolicyDecision::Allow);
    confirm.plan_digest = Some(digest('b'));
    confirm.authorization_evidence_digest = Some(digest('c'));
    confirm.policy_boundary = PolicyBoundaryAssessment::Satisfied;
    confirm.may_request_apply = true;
    let mut automatic = confirm.clone();
    automatic.mode = OperatingMode::AutomaticWithinPolicy;
    for value in [observe, recommend, confirm, automatic] {
        assert!(validator.is_valid(&serde_json::to_value(value).unwrap()));
    }
}

#[test]
fn observe_and_recommend_are_structurally_non_mutating() {
    let supported = BTreeSet::new();
    let observe = evidence(OperatingMode::Observe);
    validate_progressive_authority(&observe, &supported).unwrap();

    let mut recommend = evidence(OperatingMode::Recommend);
    recommend.proposed_decision = Some(PolicyDecision::Allow);
    validate_progressive_authority(&recommend, &supported).unwrap();

    let mut attempted = observe;
    attempted.may_request_apply = true;
    assert_eq!(
        validate_progressive_authority(&attempted, &supported),
        Err(ProgressiveAuthorityError::InvalidModeEvidence)
    );
}

#[test]
fn confirmation_and_automatic_mode_fail_closed() {
    let supported = BTreeSet::new();
    let mut confirm = evidence(OperatingMode::Confirm);
    confirm.actual_decision = None;
    confirm.proposed_decision = Some(PolicyDecision::Allow);
    confirm.plan_digest = Some(digest('b'));
    confirm.policy_boundary = PolicyBoundaryAssessment::Satisfied;
    confirm.may_request_apply = true;
    assert_eq!(
        validate_progressive_authority(&confirm, &supported),
        Err(ProgressiveAuthorityError::ApplyNotAuthorized)
    );

    confirm.mode = OperatingMode::AutomaticWithinPolicy;
    confirm.authorization_evidence_digest = Some(digest('c'));
    confirm.policy_boundary = PolicyBoundaryAssessment::Failed;
    assert_eq!(
        validate_progressive_authority(&confirm, &supported),
        Err(ProgressiveAuthorityError::PolicyBoundaryNotSatisfied)
    );
}

#[test]
fn required_unknown_extension_fails_closed() {
    let mut observe = evidence(OperatingMode::Observe);
    observe.extensions.push(ExtensionRequirement {
        id: "urn:iicp:extension:future".into(),
        class: ExtensionClass::RequiredSecurityCritical,
    });
    assert_eq!(
        validate_progressive_authority(&observe, &BTreeSet::new()),
        Err(ProgressiveAuthorityError::UnsupportedRequiredExtension(
            "urn:iicp:extension:future".into()
        ))
    );
}

#[test]
fn stale_policy_generation_fails_closed() {
    assert_eq!(
        validate_progressive_authority_for_generation(
            &evidence(OperatingMode::Observe),
            5,
            &BTreeSet::new()
        ),
        Err(ProgressiveAuthorityError::StalePolicyGeneration)
    );
}

#[test]
fn shadow_evidence_does_not_change_policy_repository_generation() {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(PolicyRevisionV1 {
            schema_version: "1".into(),
            policy_id: "policy:baseline".into(),
            revision_id: "r1".into(),
            authority: "domain:test".into(),
            scope: "application:finance".into(),
            disposition: PolicyDisposition::Stored,
            policy: json!({"eq": ["member", true]}),
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        })
        .unwrap();
    repository
        .store_binding(ApplicationBindingV1 {
            schema_version: "1".into(),
            binding_id: "binding:finance".into(),
            application_id: "application:finance".into(),
            authority: "domain:test".into(),
            policies: vec![PolicyReferenceV1 {
                policy_id: "policy:baseline".into(),
                revision_id: "r1".into(),
                authority_rank: 100,
                mandatory: true,
                order: 1,
            }],
            policy_sets: vec![],
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        })
        .unwrap();
    assert!(repository.active("binding:finance").is_none());
    validate_progressive_authority(&evidence(OperatingMode::Observe), &BTreeSet::new()).unwrap();
    assert!(repository.active("binding:finance").is_none());
}
