use crate::runtime_observation::{validate_runtime_observation, RuntimeObservationV1};
use crate::{digest, validate_bundle, DesiredStateBundle, ManagedResource};
use iicp_client::runtime_config::{OperatingMode, RuntimeConfigV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const BOOTSTRAP_SCHEMA: &str = "iicp.management-bootstrap-assessment.v1";
pub const DOCTOR_SCHEMA: &str = "iicp.management-doctor-report.v1";
pub const FRICTION_SCHEMA: &str = "iicp.management-friction-evidence.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentMode {
    Public,
    Private,
    FederatedPrivate,
    LocalOnly,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Candidate,
    Verified,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentReadiness {
    ReadyForProposal,
    NeedsInput,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentObservationV1 {
    pub observation_id: String,
    pub kind: String,
    pub source: String,
    pub status: ObservationStatus,
    pub observed_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredDecisionV1 {
    pub decision_id: String,
    pub prompt: String,
    pub security_sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapRecommendationV1 {
    pub recommendation_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ManagedResource>,
    #[serde(default)]
    pub requires_decision_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAssessmentV1 {
    pub schema_version: String,
    pub assessment_id: String,
    pub environment_mode: EnvironmentMode,
    pub observed_at: u64,
    pub expires_at: u64,
    pub readiness: AssessmentReadiness,
    pub authorizes_mutation: bool,
    pub observations: Vec<EnvironmentObservationV1>,
    #[serde(default)]
    pub recommendations: Vec<BootstrapRecommendationV1>,
    #[serde(default)]
    pub required_decisions: Vec<RequiredDecisionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckState {
    Pass,
    Warn,
    Fail,
    NotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheckV1 {
    pub check_id: String,
    pub state: CheckState,
    pub reason_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReportV1 {
    pub schema_version: String,
    pub assessment_id: String,
    pub authorizes_mutation: bool,
    pub checks: Vec<DoctorCheckV1>,
    pub overall: CheckState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrictionEvidenceV1 {
    pub schema_version: String,
    pub evidence_id: String,
    pub evidence_class: String,
    pub workflow: String,
    pub actor_class: String,
    pub started_at: u64,
    pub completed_at: u64,
    pub interaction_count: u64,
    pub outcome: String,
    pub representative: bool,
    pub authorizes_mutation: bool,
}

pub fn assessment_from_runtime_config(
    config: &RuntimeConfigV1,
    resource_id: &str,
    runtime: Option<&RuntimeObservationV1>,
    now: u64,
) -> Result<BootstrapAssessmentV1, String> {
    if resource_id.trim().is_empty() || resource_id.len() > 256 || !config.validate().is_empty() {
        return Err("BOOTSTRAP_RUNTIME_CONFIG_INVALID".into());
    }
    if let Some(runtime) = runtime {
        validate_runtime_observation(runtime, now)?;
        if runtime.target_id != resource_id {
            return Err("BOOTSTRAP_RUNTIME_TARGET_MISMATCH".into());
        }
    }

    let config_digest = digest(config).map_err(|error| error.to_string())?;
    let short_digest = config_digest
        .strip_prefix("sha256:")
        .and_then(|value| value.get(..16))
        .ok_or("BOOTSTRAP_RUNTIME_CONFIG_DIGEST_INVALID")?
        .to_string();
    let environment_mode = match config.mode {
        OperatingMode::Public => EnvironmentMode::Public,
        OperatingMode::Private => EnvironmentMode::Private,
        OperatingMode::FederatedPrivate => EnvironmentMode::FederatedPrivate,
        OperatingMode::LocalOnly => EnvironmentMode::LocalOnly,
        OperatingMode::Custom => EnvironmentMode::Custom,
    };
    let expires_at = now
        .checked_add(300)
        .ok_or("BOOTSTRAP_ASSESSMENT_TIME_INVALID")?;
    let mut observations = vec![EnvironmentObservationV1 {
        observation_id: format!("runtime-config:{short_digest}"),
        kind: "runtime_config".into(),
        source: "iicp.runtime-config.v1".into(),
        status: ObservationStatus::Verified,
        observed_at: now,
        expires_at,
        evidence_digest: Some(config_digest),
        details: serde_json::json!({
            "schema_version": config.schema_version,
            "mode": config.mode,
            "directory_source": config.directory.source,
        }),
    }];
    if let Some(runtime) = runtime {
        let runtime_short = runtime
            .source_digest
            .strip_prefix("sha256:")
            .and_then(|value| value.get(..16))
            .ok_or("BOOTSTRAP_RUNTIME_DIGEST_INVALID")?;
        observations.push(EnvironmentObservationV1 {
            observation_id: format!("runtime-health:{runtime_short}"),
            kind: "runtime_health".into(),
            source: runtime.evidence_source.clone(),
            status: ObservationStatus::Verified,
            observed_at: now,
            expires_at,
            evidence_digest: Some(runtime.source_digest.clone()),
            details: serde_json::json!({
                "evidence_state": runtime.evidence_state,
                "effective_state": runtime.effective_state,
                "reported_liveness": runtime.reported_liveness,
                "reported_readiness": runtime.reported_readiness,
                "reason_codes": runtime.reason_codes,
            }),
        });
    }

    let assessment = BootstrapAssessmentV1 {
        schema_version: BOOTSTRAP_SCHEMA.into(),
        assessment_id: format!("runtime-config:{short_digest}"),
        environment_mode,
        observed_at: now,
        expires_at,
        readiness: AssessmentReadiness::ReadyForProposal,
        authorizes_mutation: false,
        observations,
        recommendations: vec![BootstrapRecommendationV1 {
            recommendation_id: format!("manage:{resource_id}"),
            reason: "manage the validated canonical runtime configuration".into(),
            resource: Some(ManagedResource {
                resource_id: resource_id.into(),
                kind: "RuntimeConfigV1".into(),
                desired: serde_json::to_value(config)
                    .map_err(|_| "BOOTSTRAP_RUNTIME_CONFIG_SERIALIZATION_FAILED")?,
                secret_refs: Default::default(),
            }),
            requires_decision_ids: Vec::new(),
        }],
        required_decisions: Vec::new(),
    };
    validate_assessment(&assessment, now)?;
    Ok(assessment)
}

pub fn validate_assessment(value: &BootstrapAssessmentV1, now: u64) -> Result<(), String> {
    if value.schema_version != BOOTSTRAP_SCHEMA
        || value.authorizes_mutation
        || value.assessment_id.is_empty()
        || value.observed_at > now
        || now > value.expires_at
        || value.observations.len() > 1024
        || value.recommendations.len() > 1024
        || value.required_decisions.len() > 1024
    {
        return Err("BOOTSTRAP_ASSESSMENT_INVALID".into());
    }
    let decisions = value
        .required_decisions
        .iter()
        .map(|item| item.decision_id.as_str())
        .collect::<BTreeSet<_>>();
    if decisions.len() != value.required_decisions.len() {
        return Err("BOOTSTRAP_DECISION_DUPLICATE".into());
    }
    for observation in &value.observations {
        if observation.observation_id.is_empty()
            || observation.kind.is_empty()
            || observation.source.is_empty()
            || observation.observed_at > observation.expires_at
            || now > observation.expires_at
            || contains_secret(&observation.details)
        {
            return Err("BOOTSTRAP_OBSERVATION_INVALID".into());
        }
        if observation.status == ObservationStatus::Verified
            && observation
                .evidence_digest
                .as_deref()
                .is_none_or(|d| !valid_digest(d))
        {
            return Err("BOOTSTRAP_VERIFICATION_EVIDENCE_REQUIRED".into());
        }
    }
    for recommendation in &value.recommendations {
        if recommendation.recommendation_id.is_empty()
            || recommendation.reason.is_empty()
            || recommendation
                .requires_decision_ids
                .iter()
                .any(|id| !decisions.contains(id.as_str()))
            || recommendation
                .resource
                .as_ref()
                .is_some_and(|resource| contains_secret(&resource.desired))
        {
            return Err("BOOTSTRAP_RECOMMENDATION_INVALID".into());
        }
    }
    let expected = if value
        .observations
        .iter()
        .any(|item| item.status == ObservationStatus::Failed)
    {
        AssessmentReadiness::Blocked
    } else if !value.required_decisions.is_empty()
        || value
            .observations
            .iter()
            .any(|item| item.status != ObservationStatus::Verified)
    {
        AssessmentReadiness::NeedsInput
    } else {
        AssessmentReadiness::ReadyForProposal
    };
    if value.readiness != expected {
        return Err("BOOTSTRAP_READINESS_INVALID".into());
    }
    if matches!(
        value.environment_mode,
        EnvironmentMode::Private | EnvironmentMode::LocalOnly | EnvironmentMode::FederatedPrivate
    ) && value.recommendations.iter().any(|item| {
        item.resource
            .as_ref()
            .is_some_and(|r| r.desired.to_string().contains("https://iicp.network/api"))
    }) {
        return Err("BOOTSTRAP_PUBLIC_FALLBACK_FORBIDDEN".into());
    }
    Ok(())
}

pub fn doctor(
    value: &BootstrapAssessmentV1,
    now: u64,
    controller_status: Option<bool>,
    adapter_status: Option<bool>,
) -> DoctorReportV1 {
    let assessment_valid = validate_assessment(value, now).is_ok();
    let mut checks = vec![DoctorCheckV1 {
        check_id: "assessment".into(),
        state: if assessment_valid {
            CheckState::Pass
        } else {
            CheckState::Fail
        },
        reason_code: if assessment_valid {
            "ASSESSMENT_VALID"
        } else {
            "ASSESSMENT_INVALID"
        }
        .into(),
    }];
    checks.push(DoctorCheckV1 {
        check_id: "controller".into(),
        state: match controller_status {
            Some(true) => CheckState::Pass,
            Some(false) => CheckState::Fail,
            None => CheckState::NotAvailable,
        },
        reason_code: match controller_status {
            Some(true) => "CONTROLLER_READABLE",
            Some(false) => "CONTROLLER_INVALID",
            None => "CONTROLLER_NOT_PROVIDED",
        }
        .into(),
    });
    checks.push(DoctorCheckV1 {
        check_id: "adapter".into(),
        state: match adapter_status {
            Some(true) => CheckState::Pass,
            Some(false) => CheckState::Fail,
            None => CheckState::NotAvailable,
        },
        reason_code: match adapter_status {
            Some(true) => "ADAPTER_EVIDENCE_VALID",
            Some(false) => "ADAPTER_EVIDENCE_INVALID",
            None => "ADAPTER_EVIDENCE_NOT_PROVIDED",
        }
        .into(),
    });
    let overall = if checks.iter().any(|c| c.state == CheckState::Fail) {
        CheckState::Fail
    } else if checks
        .iter()
        .any(|c| matches!(c.state, CheckState::Warn | CheckState::NotAvailable))
    {
        CheckState::Warn
    } else {
        CheckState::Pass
    };
    DoctorReportV1 {
        schema_version: DOCTOR_SCHEMA.into(),
        assessment_id: value.assessment_id.clone(),
        authorizes_mutation: false,
        checks,
        overall,
    }
}

pub fn create_proposal(
    value: &BootstrapAssessmentV1,
    issuer: &str,
    audience: &str,
    generation: u64,
    now: u64,
) -> Result<DesiredStateBundle, String> {
    validate_assessment(value, now)?;
    if value.readiness != AssessmentReadiness::ReadyForProposal {
        return Err("BOOTSTRAP_NOT_READY".into());
    }
    let resources = value
        .recommendations
        .iter()
        .filter_map(|item| item.resource.clone())
        .collect();
    let bundle = DesiredStateBundle {
        schema_version: "1".into(),
        bundle_id: format!("bootstrap:{}", value.assessment_id),
        issuer: issuer.into(),
        audience: audience.into(),
        expected_generation: generation,
        resources,
        extensions: Vec::new(),
    };
    validate_bundle(&bundle, &BTreeSet::new(), 1024).map_err(|error| error.to_string())?;
    Ok(bundle)
}

pub fn validate_import(bundle: &DesiredStateBundle) -> Result<String, String> {
    validate_bundle(bundle, &BTreeSet::new(), 1024).map_err(|error| error.to_string())?;
    digest(bundle).map_err(|error| error.to_string())
}

pub fn validate_friction(value: &FrictionEvidenceV1) -> Result<(), String> {
    if value.schema_version != FRICTION_SCHEMA
        || value.evidence_id.is_empty()
        || value.evidence_class.is_empty()
        || value.workflow.is_empty()
        || value.actor_class.is_empty()
        || value.completed_at < value.started_at
        || value.outcome.is_empty()
        || value.authorizes_mutation
    {
        return Err("FRICTION_EVIDENCE_INVALID".into());
    }
    if value.evidence_class == "project_rehearsal" && value.representative {
        return Err("FRICTION_REPRESENTATIVE_CLAIM_INVALID".into());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|b| b.is_ascii_hexdigit())
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
