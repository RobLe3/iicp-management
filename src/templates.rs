use crate::policy_lifecycle::{
    repository_from_workspace, ApplicationBindingV1, PolicyDisposition, PolicyReferenceV1,
    PolicyRevisionV1, PolicyWorkspaceV1,
};
use crate::{digest, PolicyDecision};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const TEMPLATE_SCHEMA: &str = "iicp.management-policy-template.v1";
pub const TEMPLATE_RENDER_SCHEMA: &str = "iicp.management-template-render.v1";
pub const IMPACT_SCHEMA: &str = "iicp.management-policy-impact.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateParameterType {
    String,
    Boolean,
    Number,
    StringArray,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TemplateParameterV1 {
    pub parameter_id: String,
    pub value_type: TemplateParameterType,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default)]
    pub allowed_values: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateOperator {
    Eq,
    In,
    Contains,
    Lte,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum TemplateExpectedV1 {
    Literal { value: Value },
    Parameter { parameter_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TemplateConstraintV1 {
    pub constraint_id: String,
    pub fact: String,
    pub operator: TemplateOperator,
    pub expected: TemplateExpectedV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyTemplateV1 {
    pub schema_version: String,
    pub template_id: String,
    pub revision_id: String,
    pub title: String,
    pub description: String,
    pub provenance: String,
    pub compatibility_profile: String,
    pub authorizes_activation: bool,
    #[serde(default)]
    pub parameters: Vec<TemplateParameterV1>,
    pub constraints: Vec<TemplateConstraintV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TemplateRenderRequestV1 {
    pub schema_version: String,
    pub template_id: String,
    pub revision_id: String,
    pub authority: String,
    pub scope: String,
    pub application_id: String,
    pub binding_id: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RenderedPolicyTemplateV1 {
    pub schema_version: String,
    pub template_id: String,
    pub template_revision_id: String,
    pub template_digest: String,
    pub authorizes_activation: bool,
    pub workspace: PolicyWorkspaceV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricObservationV1 {
    pub value: Value,
    pub unit: String,
    pub evidence_digest: String,
    pub observed_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ImpactCandidateV1 {
    pub candidate_id: String,
    pub facts: Value,
    pub compatibility: CompatibilityStatus,
    #[serde(default)]
    pub metrics: BTreeMap<String, MetricObservationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ImpactRequestV1 {
    pub schema_version: String,
    pub current: PolicyWorkspaceV1,
    pub proposed: PolicyWorkspaceV1,
    pub candidates: Vec<ImpactCandidateV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceAvailability {
    Supplied,
    NotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricProjectionV1 {
    pub availability: EvidenceAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FallbackStatus {
    Available,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CandidateImpactV1 {
    pub candidate_id: String,
    pub current_decision: PolicyDecision,
    pub proposed_decision: PolicyDecision,
    pub decision_changed: bool,
    pub newly_allowed: bool,
    pub newly_denied: bool,
    pub unresolved_evidence: bool,
    pub compatibility: CompatibilityStatus,
    pub fallback: FallbackStatus,
    pub metrics: BTreeMap<String, MetricProjectionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ImpactReportV1 {
    pub schema_version: String,
    pub authorizes_mutation: bool,
    pub affected_candidates: u64,
    pub newly_allowed: u64,
    pub newly_denied: u64,
    pub unresolved_evidence: u64,
    pub incompatible: u64,
    pub missing_fallback: u64,
    pub entries: Vec<CandidateImpactV1>,
}

pub fn builtin_templates() -> Vec<PolicyTemplateV1> {
    vec![
        template(
            "internal-only",
            "Internal infrastructure only",
            "Allow only provider classes explicitly listed as internal.",
            vec![string_array_parameter(
                "allowed_provider_classes",
                vec![json!("internal")],
            )],
            vec![parameter_constraint(
                "provider-class",
                "provider_class",
                TemplateOperator::In,
                "allowed_provider_classes",
            )],
        ),
        template(
            "eu-processing",
            "EU processing",
            "Allow only explicitly listed EU processing regions.",
            vec![string_array_parameter("allowed_regions", vec![json!("EU")])],
            vec![parameter_constraint(
                "processing-region",
                "region",
                TemplateOperator::In,
                "allowed_regions",
            )],
        ),
        template(
            "maximum-privacy",
            "Maximum privacy",
            "Require local execution and a no-retention provider declaration.",
            vec![],
            vec![
                literal_constraint(
                    "local-execution",
                    "remote_execution",
                    TemplateOperator::Eq,
                    json!(false),
                ),
                literal_constraint(
                    "no-retention",
                    "retention_mode",
                    TemplateOperator::Eq,
                    json!("none"),
                ),
            ],
        ),
        template(
            "high-availability",
            "High availability",
            "Require explicit evidence that an eligible fallback is available.",
            vec![],
            vec![literal_constraint(
                "fallback-available",
                "fallback_available",
                TemplateOperator::Eq,
                json!(true),
            )],
        ),
    ]
}

pub fn template_by_id(id: &str, revision: &str) -> Option<PolicyTemplateV1> {
    builtin_templates()
        .into_iter()
        .find(|item| item.template_id == id && item.revision_id == revision)
}

pub fn validate_template(value: &PolicyTemplateV1) -> Result<(), String> {
    if value.schema_version != TEMPLATE_SCHEMA
        || value.authorizes_activation
        || !identifiers(&[
            &value.template_id,
            &value.revision_id,
            &value.title,
            &value.description,
            &value.provenance,
            &value.compatibility_profile,
        ])
        || value.parameters.len() > 32
        || value.constraints.is_empty()
        || value.constraints.len() > 64
    {
        return Err("TEMPLATE_INVALID".into());
    }
    let mut parameter_ids = BTreeSet::new();
    for parameter in &value.parameters {
        if !parameter_ids.insert(parameter.parameter_id.as_str())
            || parameter.parameter_id.is_empty()
            || parameter.default.as_ref().is_some_and(contains_secret)
            || parameter
                .default
                .as_ref()
                .is_some_and(|item| !matches_type(item, &parameter.value_type))
            || parameter.allowed_values.iter().any(|item| {
                let type_matches = if parameter.value_type == TemplateParameterType::StringArray {
                    item.is_string()
                } else {
                    matches_type(item, &parameter.value_type)
                };
                !type_matches || contains_secret(item)
            })
        {
            return Err("TEMPLATE_PARAMETER_INVALID".into());
        }
    }
    let mut constraints = BTreeSet::new();
    for constraint in &value.constraints {
        if !constraints.insert(constraint.constraint_id.as_str())
            || !identifiers(&[&constraint.constraint_id, &constraint.fact])
            || match &constraint.expected {
                TemplateExpectedV1::Literal { value } => contains_secret(value),
                TemplateExpectedV1::Parameter { parameter_id } => {
                    !parameter_ids.contains(parameter_id.as_str())
                }
            }
        {
            return Err("TEMPLATE_CONSTRAINT_INVALID".into());
        }
    }
    Ok(())
}

pub fn render_template(
    template: &PolicyTemplateV1,
    request: &TemplateRenderRequestV1,
) -> Result<RenderedPolicyTemplateV1, String> {
    validate_template(template)?;
    if request.schema_version != TEMPLATE_RENDER_SCHEMA
        || request.template_id != template.template_id
        || request.revision_id != template.revision_id
        || !identifiers(&[
            &request.authority,
            &request.scope,
            &request.application_id,
            &request.binding_id,
        ])
    {
        return Err("TEMPLATE_RENDER_INVALID".into());
    }
    let specifications = template
        .parameters
        .iter()
        .map(|item| (item.parameter_id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    if request
        .parameters
        .keys()
        .any(|id| !specifications.contains_key(id.as_str()))
    {
        return Err("TEMPLATE_PARAMETER_UNKNOWN".into());
    }
    let mut resolved = BTreeMap::new();
    for parameter in &template.parameters {
        let value = request
            .parameters
            .get(&parameter.parameter_id)
            .cloned()
            .or_else(|| parameter.default.clone())
            .ok_or_else(|| "TEMPLATE_PARAMETER_REQUIRED".to_string())?;
        if !matches_type(&value, &parameter.value_type)
            || contains_secret(&value)
            || (!parameter.allowed_values.is_empty()
                && value.as_array().map_or_else(
                    || !parameter.allowed_values.contains(&value),
                    |items| {
                        items
                            .iter()
                            .any(|item| !parameter.allowed_values.contains(item))
                    },
                ))
        {
            return Err("TEMPLATE_PARAMETER_VALUE_INVALID".into());
        }
        resolved.insert(parameter.parameter_id.clone(), value);
    }
    let rules = template
        .constraints
        .iter()
        .map(|constraint| {
            let expected = match &constraint.expected {
                TemplateExpectedV1::Literal { value } => value.clone(),
                TemplateExpectedV1::Parameter { parameter_id } => resolved
                    .get(parameter_id)
                    .cloned()
                    .ok_or_else(|| "TEMPLATE_PARAMETER_REQUIRED".to_string())?,
            };
            let operator = match constraint.operator {
                TemplateOperator::Eq => "eq",
                TemplateOperator::In => "in",
                TemplateOperator::Contains => "contains",
                TemplateOperator::Lte => "lte",
            };
            if matches!(constraint.operator, TemplateOperator::In) && !expected.is_array()
                || matches!(constraint.operator, TemplateOperator::Lte) && !expected.is_number()
            {
                return Err("TEMPLATE_CONSTRAINT_VALUE_INVALID".to_string());
            }
            Ok(json!({operator:[constraint.fact.clone(), expected]}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let policy = if rules.len() == 1 {
        rules[0].clone()
    } else {
        json!({"all":rules})
    };
    let revision = PolicyRevisionV1 {
        schema_version: "1".into(),
        policy_id: format!("policy:template:{}", template.template_id),
        revision_id: template.revision_id.clone(),
        authority: request.authority.clone(),
        scope: request.scope.clone(),
        disposition: PolicyDisposition::Stored,
        policy,
        valid_from: None,
        valid_until: None,
        extensions: vec![],
    };
    let binding = ApplicationBindingV1 {
        schema_version: "1".into(),
        binding_id: request.binding_id.clone(),
        application_id: request.application_id.clone(),
        authority: request.authority.clone(),
        policies: vec![PolicyReferenceV1 {
            policy_id: revision.policy_id.clone(),
            revision_id: revision.revision_id.clone(),
            authority_rank: 100,
            mandatory: true,
            order: 1,
        }],
        policy_sets: vec![],
        valid_from: None,
        valid_until: None,
        extensions: vec![],
    };
    Ok(RenderedPolicyTemplateV1 {
        schema_version: TEMPLATE_RENDER_SCHEMA.into(),
        template_id: template.template_id.clone(),
        template_revision_id: template.revision_id.clone(),
        template_digest: digest(template).map_err(|error| error.to_string())?,
        authorizes_activation: false,
        workspace: PolicyWorkspaceV1 {
            revisions: vec![revision],
            policy_sets: vec![],
            binding,
            activation: None,
        },
    })
}

pub fn preview_impact(request: &ImpactRequestV1, now: u64) -> Result<ImpactReportV1, String> {
    if request.schema_version != IMPACT_SCHEMA
        || request.candidates.is_empty()
        || request.candidates.len() > 10_000
    {
        return Err("IMPACT_REQUEST_INVALID".into());
    }
    let current = repository_from_workspace(request.current.clone()).map_err(|e| e.to_string())?;
    let proposed =
        repository_from_workspace(request.proposed.clone()).map_err(|e| e.to_string())?;
    let current_binding = request.current.binding.binding_id.as_str();
    let proposed_binding = request.proposed.binding.binding_id.as_str();
    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for candidate in &request.candidates {
        if !seen.insert(candidate.candidate_id.as_str())
            || candidate.candidate_id.is_empty()
            || !candidate.facts.is_object()
            || contains_secret(&candidate.facts)
            || candidate
                .metrics
                .keys()
                .any(|name| !matches!(name.as_str(), "cost" | "latency" | "quality" | "capacity"))
            || candidate.metrics.values().any(|metric| {
                metric.unit.is_empty()
                    || !valid_digest(&metric.evidence_digest)
                    || metric.observed_at > now
                    || metric.observed_at > metric.expires_at
                    || now > metric.expires_at
                    || contains_secret(&metric.value)
            })
        {
            return Err("IMPACT_CANDIDATE_INVALID".into());
        }
        let current_decision = current
            .effective_policy(current_binding, &candidate.facts)
            .map_err(|e| e.to_string())?
            .decision;
        let proposed_decision = proposed
            .effective_policy(proposed_binding, &candidate.facts)
            .map_err(|e| e.to_string())?
            .decision;
        let unresolved_evidence = current_decision == PolicyDecision::Indeterminate
            || proposed_decision == PolicyDecision::Indeterminate
            || candidate.compatibility == CompatibilityStatus::Unknown;
        let fallback = match candidate
            .facts
            .get("fallback_available")
            .and_then(Value::as_bool)
        {
            Some(true) => FallbackStatus::Available,
            Some(false) => FallbackStatus::Missing,
            None => FallbackStatus::Unknown,
        };
        let metrics = ["cost", "latency", "quality", "capacity"]
            .into_iter()
            .map(|name| {
                let projection = candidate.metrics.get(name).map_or(
                    MetricProjectionV1 {
                        availability: EvidenceAvailability::NotAvailable,
                        value: None,
                        unit: None,
                        evidence_digest: None,
                    },
                    |metric| MetricProjectionV1 {
                        availability: EvidenceAvailability::Supplied,
                        value: Some(metric.value.clone()),
                        unit: Some(metric.unit.clone()),
                        evidence_digest: Some(metric.evidence_digest.clone()),
                    },
                );
                (name.to_string(), projection)
            })
            .collect();
        entries.push(CandidateImpactV1 {
            candidate_id: candidate.candidate_id.clone(),
            decision_changed: current_decision != proposed_decision,
            newly_allowed: current_decision != PolicyDecision::Allow
                && proposed_decision == PolicyDecision::Allow,
            newly_denied: current_decision != PolicyDecision::Deny
                && proposed_decision == PolicyDecision::Deny,
            unresolved_evidence,
            compatibility: candidate.compatibility.clone(),
            fallback,
            metrics,
            current_decision,
            proposed_decision,
        });
    }
    Ok(ImpactReportV1 {
        schema_version: IMPACT_SCHEMA.into(),
        authorizes_mutation: false,
        affected_candidates: entries.iter().filter(|item| item.decision_changed).count() as u64,
        newly_allowed: entries.iter().filter(|item| item.newly_allowed).count() as u64,
        newly_denied: entries.iter().filter(|item| item.newly_denied).count() as u64,
        unresolved_evidence: entries
            .iter()
            .filter(|item| item.unresolved_evidence)
            .count() as u64,
        incompatible: entries
            .iter()
            .filter(|item| item.compatibility == CompatibilityStatus::Incompatible)
            .count() as u64,
        missing_fallback: entries
            .iter()
            .filter(|item| item.fallback == FallbackStatus::Missing)
            .count() as u64,
        entries,
    })
}

fn template(
    id: &str,
    title: &str,
    description: &str,
    parameters: Vec<TemplateParameterV1>,
    constraints: Vec<TemplateConstraintV1>,
) -> PolicyTemplateV1 {
    PolicyTemplateV1 {
        schema_version: TEMPLATE_SCHEMA.into(),
        template_id: id.into(),
        revision_id: "r1".into(),
        title: title.into(),
        description: description.into(),
        provenance: "iicp-management-reference-catalog".into(),
        compatibility_profile: "iicp.management-policy.typed-v0".into(),
        authorizes_activation: false,
        parameters,
        constraints,
    }
}

fn string_array_parameter(id: &str, values: Vec<Value>) -> TemplateParameterV1 {
    TemplateParameterV1 {
        parameter_id: id.into(),
        value_type: TemplateParameterType::StringArray,
        required: true,
        default: Some(Value::Array(values.clone())),
        allowed_values: values,
    }
}

fn parameter_constraint(
    id: &str,
    fact: &str,
    operator: TemplateOperator,
    parameter_id: &str,
) -> TemplateConstraintV1 {
    TemplateConstraintV1 {
        constraint_id: id.into(),
        fact: fact.into(),
        operator,
        expected: TemplateExpectedV1::Parameter {
            parameter_id: parameter_id.into(),
        },
    }
}

fn literal_constraint(
    id: &str,
    fact: &str,
    operator: TemplateOperator,
    value: Value,
) -> TemplateConstraintV1 {
    TemplateConstraintV1 {
        constraint_id: id.into(),
        fact: fact.into(),
        operator,
        expected: TemplateExpectedV1::Literal { value },
    }
}

fn identifiers(values: &[&str]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn matches_type(value: &Value, expected: &TemplateParameterType) -> bool {
    match expected {
        TemplateParameterType::String => value.is_string(),
        TemplateParameterType::Boolean => value.is_boolean(),
        TemplateParameterType::Number => value.is_number(),
        TemplateParameterType::StringArray => value
            .as_array()
            .is_some_and(|items| !items.is_empty() && items.iter().all(Value::is_string)),
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "secret"
                    | "secret_value"
                    | "operator_secret"
                    | "password"
                    | "token"
                    | "access_token"
                    | "refresh_token"
                    | "bearer_token"
                    | "api_key"
                    | "private_key"
                    | "prompt"
                    | "response"
                    | "task_payload"
            ) || contains_secret(value)
        }),
        Value::Array(items) => items.iter().any(contains_secret),
        _ => false,
    }
}
