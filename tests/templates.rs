use iicp_management_core::policy_lifecycle::{
    ApplicationBindingV1, PolicyDisposition, PolicyReferenceV1, PolicyRevisionV1, PolicyWorkspaceV1,
};
use iicp_management_core::templates::*;
use iicp_management_core::PolicyDecision;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn render_request(id: &str) -> TemplateRenderRequestV1 {
    TemplateRenderRequestV1 {
        schema_version: TEMPLATE_RENDER_SCHEMA.into(),
        template_id: id.into(),
        revision_id: "r1".into(),
        authority: "domain:test".into(),
        scope: "application:test".into(),
        application_id: "application:test".into(),
        binding_id: "binding:test".into(),
        parameters: BTreeMap::new(),
    }
}

fn workspace(policy_id: &str, policy: Value) -> PolicyWorkspaceV1 {
    PolicyWorkspaceV1 {
        revisions: vec![PolicyRevisionV1 {
            schema_version: "1".into(),
            policy_id: policy_id.into(),
            revision_id: "r1".into(),
            authority: "domain:test".into(),
            scope: "application:test".into(),
            disposition: PolicyDisposition::Stored,
            policy,
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        }],
        policy_sets: vec![],
        binding: ApplicationBindingV1 {
            schema_version: "1".into(),
            binding_id: "binding:test".into(),
            application_id: "application:test".into(),
            authority: "domain:test".into(),
            policies: vec![PolicyReferenceV1 {
                policy_id: policy_id.into(),
                revision_id: "r1".into(),
                authority_rank: 100,
                mandatory: true,
                order: 1,
            }],
            policy_sets: vec![],
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        },
        activation: None,
    }
}

#[test]
fn reference_catalog_is_valid_and_rendering_is_deterministic() {
    let templates = builtin_templates();
    assert_eq!(templates.len(), 4);
    for template in templates {
        validate_template(&template).unwrap();
        let request = render_request(&template.template_id);
        let first = render_template(&template, &request).unwrap();
        let second = render_template(&template, &request).unwrap();
        assert_eq!(first, second);
        assert!(!first.authorizes_activation);
        assert!(first.workspace.activation.is_none());
    }
}

#[test]
fn unknown_and_unsafe_template_parameters_fail_closed() {
    let template = template_by_id("eu-processing", "r1").unwrap();
    let mut request = render_request("eu-processing");
    request.parameters.insert("unknown".into(), json!(true));
    assert_eq!(
        render_template(&template, &request).unwrap_err(),
        "TEMPLATE_PARAMETER_UNKNOWN"
    );
    request.parameters.clear();
    request
        .parameters
        .insert("allowed_regions".into(), json!(["US"]));
    assert_eq!(
        render_template(&template, &request).unwrap_err(),
        "TEMPLATE_PARAMETER_VALUE_INVALID"
    );
}

#[test]
fn operator_and_expected_value_shape_are_checked_before_rendering() {
    let mut template = template_by_id("high-availability", "r1").unwrap();
    template.constraints[0].operator = TemplateOperator::In;
    assert_eq!(
        render_template(&template, &render_request("high-availability")).unwrap_err(),
        "TEMPLATE_CONSTRAINT_VALUE_INVALID"
    );
}

#[test]
fn impact_preview_is_evidence_bound_and_non_authorizing() {
    let request = ImpactRequestV1 {
        schema_version: IMPACT_SCHEMA.into(),
        current: workspace("policy:current", json!({"eq":["member",true]})),
        proposed: workspace("policy:proposed", json!({"eq":["region","EU"]})),
        candidates: vec![ImpactCandidateV1 {
            candidate_id: "candidate:one".into(),
            facts: json!({"member":true,"region":"US","fallback_available":false}),
            compatibility: CompatibilityStatus::Compatible,
            metrics: BTreeMap::new(),
        }],
    };
    let report = preview_impact(&request, 100).unwrap();
    assert!(!report.authorizes_mutation);
    assert_eq!(report.newly_denied, 1);
    assert_eq!(report.missing_fallback, 1);
    assert_eq!(report.entries[0].current_decision, PolicyDecision::Allow);
    assert_eq!(report.entries[0].proposed_decision, PolicyDecision::Deny);
    for projection in report.entries[0].metrics.values() {
        assert_eq!(projection.availability, EvidenceAvailability::NotAvailable);
        assert!(projection.value.is_none());
    }
    let schema: Value =
        serde_json::from_str(include_str!("../contracts/policy-impact-v1.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&serde_json::to_value(report).unwrap()));
}

#[test]
fn supplied_metric_requires_fresh_integrity_evidence() {
    let mut metrics = BTreeMap::new();
    metrics.insert(
        "cost".into(),
        MetricObservationV1 {
            value: json!(0.25),
            unit: "EUR/request".into(),
            evidence_digest: format!("sha256:{}", "a".repeat(64)),
            observed_at: 90,
            expires_at: 110,
        },
    );
    let mut request = ImpactRequestV1 {
        schema_version: IMPACT_SCHEMA.into(),
        current: workspace("policy:current", json!({"eq":["member",true]})),
        proposed: workspace("policy:proposed", json!({"eq":["member",true]})),
        candidates: vec![ImpactCandidateV1 {
            candidate_id: "candidate:one".into(),
            facts: json!({"member":true}),
            compatibility: CompatibilityStatus::Unknown,
            metrics,
        }],
    };
    let report = preview_impact(&request, 100).unwrap();
    assert_eq!(report.unresolved_evidence, 1);
    assert_eq!(
        report.entries[0].metrics["cost"].availability,
        EvidenceAvailability::Supplied
    );
    request.candidates[0]
        .metrics
        .get_mut("cost")
        .unwrap()
        .expires_at = 99;
    assert_eq!(
        preview_impact(&request, 100).unwrap_err(),
        "IMPACT_CANDIDATE_INVALID"
    );
}

#[test]
fn cli_lists_and_renders_reference_templates() {
    let list = std::process::Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args(["--json", "template", "list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let catalog: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(catalog.as_array().unwrap().len(), 4);

    let directory = tempfile::tempdir().unwrap();
    let request_path = directory.path().join("render.json");
    std::fs::write(
        &request_path,
        serde_json::to_vec_pretty(&render_request("internal-only")).unwrap(),
    )
    .unwrap();
    let render = std::process::Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args(["template", "render", request_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(render.status.success());
    let rendered: Value = serde_json::from_slice(&render.stdout).unwrap();
    assert_eq!(rendered["authorizes_activation"], false);

    let impact = std::process::Command::new(env!("CARGO_BIN_EXE_iicp-management"))
        .args([
            "--json",
            "impact",
            "preview",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/examples/templates/impact-request.json"
            ),
        ])
        .output()
        .unwrap();
    assert!(impact.status.success());
    let report: Value = serde_json::from_slice(&impact.stdout).unwrap();
    assert_eq!(report["authorizes_mutation"], false);
    assert_eq!(report["newly_denied"], 1);
}

#[test]
fn public_template_schema_accepts_the_reference_catalog() {
    let schema: Value =
        serde_json::from_str(include_str!("../contracts/policy-template-v1.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for template in builtin_templates() {
        assert!(validator.is_valid(&serde_json::to_value(template).unwrap()));
    }
}
