use iicp_management_core::*;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

fn bundle(resources: Vec<ManagedResource>) -> DesiredStateBundle {
    DesiredStateBundle {
        schema_version: "1".into(),
        bundle_id: "bundle-1".into(),
        issuer: "did:iicp:controller:test".into(),
        audience: "domain:test".into(),
        expected_generation: 7,
        resources,
        extensions: vec![],
    }
}

fn resource(id: &str, value: i64) -> ManagedResource {
    ManagedResource {
        resource_id: id.into(),
        kind: "runtime-config".into(),
        desired: json!({"value": value, "nested": {"enabled": true}}),
        secret_refs: BTreeMap::new(),
    }
}

fn accepted() -> AcceptedState {
    AcceptedState {
        generation: 7,
        resource_digests: BTreeMap::new(),
    }
}

#[test]
fn equivalent_input_order_produces_identical_plan_digest() {
    let a = plan(
        &bundle(vec![resource("b", 2), resource("a", 1)]),
        &accepted(),
        &BTreeSet::new(),
        10,
    )
    .unwrap();
    let b = plan(
        &bundle(vec![resource("a", 1), resource("b", 2)]),
        &accepted(),
        &BTreeSet::new(),
        10,
    )
    .unwrap();
    assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
    assert_eq!(a.operations[0].resource_id, "a");
}

#[test]
fn digest_uses_rfc8785_canonical_member_order() {
    assert_eq!(
        digest(&json!({"b": 1, "a": 2})).unwrap(),
        "sha256:d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772"
    );
}

#[test]
fn portable_planning_vector_matches_reference_core() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../fixtures/management-portable-conformance-v1.json"
    ))
    .unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "EM1-PLAN-01")
        .unwrap();
    let input: DesiredStateBundle =
        serde_json::from_value(case["input"]["bundle"].clone()).unwrap();
    let accepted: AcceptedState =
        serde_json::from_value(case["input"]["accepted"].clone()).unwrap();
    let actual = plan(&input, &accepted, &BTreeSet::new(), 10).unwrap();
    assert_eq!(serde_json::to_value(actual).unwrap(), case["expected"]);
}

#[test]
fn stale_generation_fails_closed() {
    let mut input = bundle(vec![resource("a", 1)]);
    input.expected_generation = 6;
    assert_eq!(
        plan(&input, &accepted(), &BTreeSet::new(), 10),
        Err(ManagementError::StaleGeneration)
    );
}

#[test]
fn unknown_required_and_security_extensions_fail_closed() {
    for class in [
        ExtensionClass::RequiredUnderstood,
        ExtensionClass::RequiredSecurityCritical,
    ] {
        let mut input = bundle(vec![resource("a", 1)]);
        input.extensions.push(ExtensionRequirement {
            id: "urn:iicp:profile:unknown:v1".into(),
            class,
        });
        assert!(matches!(
            plan(&input, &accepted(), &BTreeSet::new(), 10),
            Err(ManagementError::UnsupportedRequiredExtension(_))
        ));
    }
}

#[test]
fn optional_unknown_extension_does_not_widen_plan() {
    let baseline = plan(
        &bundle(vec![resource("a", 1)]),
        &accepted(),
        &BTreeSet::new(),
        10,
    )
    .unwrap();
    let mut input = bundle(vec![resource("a", 1)]);
    input.extensions.push(ExtensionRequirement {
        id: "urn:iicp:profile:optional:v1".into(),
        class: ExtensionClass::OptionalIgnorable,
    });
    let extended = plan(&input, &accepted(), &BTreeSet::new(), 10).unwrap();
    assert_eq!(baseline.operations, extended.operations);
}

#[test]
fn inline_secrets_are_rejected_but_references_are_allowed() {
    let mut unsafe_resource = resource("a", 1);
    unsafe_resource.desired = json!({"password": "not-allowed"});
    assert_eq!(
        plan(
            &bundle(vec![unsafe_resource]),
            &accepted(),
            &BTreeSet::new(),
            10
        ),
        Err(ManagementError::InlineSecret)
    );

    let mut safe_resource = resource("a", 1);
    safe_resource
        .secret_refs
        .insert("api_key".into(), "keychain://iicp/test".into());
    assert!(plan(
        &bundle(vec![safe_resource]),
        &accepted(),
        &BTreeSet::new(),
        10
    )
    .is_ok());
}

#[test]
fn approval_is_bound_to_exact_plan_audience_and_generation() {
    let plan = plan(
        &bundle(vec![resource("a", 1)]),
        &accepted(),
        &BTreeSet::new(),
        10,
    )
    .unwrap();
    let approval = Approval {
        schema_version: "1".into(),
        approval_id: "approval-1".into(),
        audience: "domain:test".into(),
        bundle_digest: plan.bundle_digest.clone(),
        plan_digest: digest(&plan).unwrap(),
        expected_generation: 7,
    };
    assert_eq!(authorize_plan(&approval, &plan, "domain:test"), Ok(()));
    assert_eq!(
        authorize_plan(&approval, &plan, "domain:other"),
        Err(ManagementError::WrongAudience)
    );

    let mut changed = plan.clone();
    changed.operations[0].after_digest = "sha256:changed".into();
    assert_eq!(
        authorize_plan(&approval, &changed, "domain:test"),
        Err(ManagementError::ApprovalDigestMismatch)
    );
}

#[test]
fn receipt_effective_state_is_derived_and_bound_to_the_exact_plan() {
    let plan = plan(
        &bundle(vec![resource("a", 1), resource("b", 2)]),
        &accepted(),
        &BTreeSet::new(),
        10,
    )
    .unwrap();
    let observations = vec![
        Observation {
            schema_version: "1".into(),
            resource_id: "a".into(),
            observed_generation: plan.target_generation,
            observed_digest: plan.operations[0].after_digest.clone(),
            state: ConvergenceState::Converged,
        },
        Observation {
            schema_version: "1".into(),
            resource_id: "b".into(),
            observed_generation: plan.target_generation,
            observed_digest: plan.operations[1].before_digest.clone(),
            state: ConvergenceState::Failed,
        },
    ];
    let mut receipt = Receipt {
        schema_version: "1".into(),
        receipt_id: "receipt-1".into(),
        audience: "domain:test".into(),
        bundle_digest: plan.bundle_digest.clone(),
        plan_digest: digest(&plan).unwrap(),
        accepted_generation: plan.target_generation,
        effective_state: derive_effective_state(&observations),
        observations,
    };
    assert_eq!(
        receipt.effective_state,
        ConvergenceState::PartiallyConverged
    );
    assert_eq!(verify_receipt(&receipt, &plan, "domain:test"), Ok(()));

    receipt.effective_state = ConvergenceState::Converged;
    assert_eq!(
        verify_receipt(&receipt, &plan, "domain:test"),
        Err(ManagementError::ReceiptStateMismatch)
    );
    receipt.effective_state = ConvergenceState::PartiallyConverged;
    receipt.plan_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert_eq!(
        verify_receipt(&receipt, &plan, "domain:test"),
        Err(ManagementError::ReceiptBindingMismatch)
    );
}

#[test]
fn resource_limit_is_bounded() {
    assert_eq!(
        plan(
            &bundle(vec![resource("a", 1), resource("b", 2)]),
            &accepted(),
            &BTreeSet::new(),
            1
        ),
        Err(ManagementError::ResourceLimit)
    );
}

#[test]
fn cancelled_planning_does_not_emit_a_plan() {
    assert_eq!(
        plan_with_control(
            &bundle(vec![resource("a", 1)]),
            &accepted(),
            &BTreeSet::new(),
            PlanningControl {
                max_resources: 10,
                cancelled: true,
            }
        ),
        Err(ManagementError::Cancelled)
    );
}

#[test]
fn published_schema_accepts_canonical_bundle_and_plan() {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-contract-v1.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let input = bundle(vec![resource("a", 1)]);
    let planned = plan(&input, &accepted(), &BTreeSet::new(), 10).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(input).unwrap()));
    assert!(validator.is_valid(&serde_json::to_value(planned).unwrap()));
    assert!(validator.is_valid(&serde_json::to_value(accepted()).unwrap()));
    let policy_result = evaluate_policy(&json!({"x": true}), &json!({"eq": ["x", true]})).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(policy_result).unwrap()));
}

#[test]
fn conformance_fixture_has_stable_unique_cases() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/management-foundation-v1.json")).unwrap();
    assert_eq!(fixture["evidence_class"], "project-verified");
    let cases = fixture["cases"].as_array().unwrap();
    let ids: BTreeSet<_> = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), cases.len());
    assert!(ids.contains("EM1-06"));
}

#[test]
fn policy_architecture_cases_are_executable() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/policy-evaluator-cases-v0.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let result = evaluate_policy(&case["input"], &case["policy"]).unwrap();
        let expected_decision = case["expected"]["decision"].as_str().unwrap();
        let actual_decision = match result.decision {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny => "deny",
            PolicyDecision::Indeterminate => "indeterminate",
        };
        assert_eq!(actual_decision, expected_decision, "case {}", case["id"]);
        assert_eq!(
            result.reason_codes[0],
            case["expected"]["reason_codes"][0].as_str().unwrap(),
            "case {}",
            case["id"]
        );
    }
}

fn reason(result: PolicyResult) -> String {
    result.reason_codes[0].clone()
}

#[test]
fn named_rules_resolve_without_changing_the_historical_policy_digest() {
    let policy = json!({
        "rules": {
            "eligible": {"all": [{"eq": ["approved", true]}, {"ref": "capacity"}]},
            "capacity": {"lte": ["load", 80]}
        },
        "entry": {"ref": "eligible"}
    });
    let result = evaluate_policy(&json!({"approved": true, "load": 40}), &policy).unwrap();
    assert_eq!(result.decision, PolicyDecision::Allow);
    assert_eq!(result.policy_digest, digest(&policy).unwrap());
}

#[test]
fn local_limits_may_narrow_every_typed_profile_budget() {
    let limits = EvaluationLimits {
        policy_bytes: 10,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(&json!({}), &json!({"eq": ["x", true]}), limits).unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        context_bytes: 2,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(&json!({"x": true}), &json!({"eq": ["x", true]}), limits)
                .unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        rules: 1,
        ..EvaluationLimits::default()
    };
    let policy = json!({"rules": {"a": {"eq": ["x", true]}, "b": {"eq": ["x", true]}}, "entry": {"ref": "a"}});
    assert_eq!(
        reason(evaluate_policy_with_limits(&json!({"x": true}), &policy, limits).unwrap()),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        ast_nodes_per_rule: 3,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(
                &json!({"x": true}),
                &json!({"all": [{"eq": ["x", true]}]}),
                limits
            )
            .unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        expression_depth: 2,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(
                &json!({"x": true}),
                &json!({"all": [{"all": [{"eq": ["x", true]}]}]}),
                limits
            )
            .unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        collection_values: 1,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(
                &json!({"regions": ["de", "fr"]}),
                &json!({"contains": ["regions", "de"]}),
                limits
            )
            .unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );
}

#[test]
fn reference_fuel_and_wall_clock_limits_fail_closed() {
    let policy = json!({
        "rules": {
            "a": {"ref": "b"},
            "b": {"ref": "c"},
            "c": {"eq": ["x", true]}
        },
        "entry": {"ref": "a"}
    });
    let limits = EvaluationLimits {
        reference_depth: 2,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(evaluate_policy_with_limits(&json!({"x": true}), &policy, limits).unwrap()),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        fuel: 1,
        ..EvaluationLimits::default()
    };
    let policy = json!({"all": [{"eq": ["x", true]}, {"eq": ["y", true]}]});
    assert_eq!(
        reason(
            evaluate_policy_with_limits(&json!({"x": true, "y": true}), &policy, limits).unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );

    let limits = EvaluationLimits {
        wall_clock: std::time::Duration::ZERO,
        ..EvaluationLimits::default()
    };
    assert_eq!(
        reason(
            evaluate_policy_with_limits(&json!({"x": true}), &json!({"eq": ["x", true]}), limits)
                .unwrap()
        ),
        "IICP-POLICY-LIMIT-EXCEEDED"
    );
}

#[test]
fn implementations_cannot_silently_raise_profile_limits() {
    let mut limits = EvaluationLimits::default();
    limits.fuel += 1;
    assert_eq!(
        reason(
            evaluate_policy_with_limits(&json!({"x": true}), &json!({"eq": ["x", true]}), limits)
                .unwrap()
        ),
        "IICP-POLICY-INPUT-INVALID"
    );
}
