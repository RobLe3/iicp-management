use crate::{ExtensionClass, ExtensionRequirement, PolicyDecision};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const PROGRESSIVE_AUTHORITY_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperatingMode {
    Observe,
    Recommend,
    Confirm,
    AutomaticWithinPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyBoundaryAssessment {
    Satisfied,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProgressiveAuthorityEvidenceV1 {
    pub schema_version: String,
    pub evidence_id: String,
    pub mode: OperatingMode,
    pub application_id: String,
    pub intent: String,
    pub policy_generation: u64,
    pub fact_snapshot_digest: String,
    pub observed_at: u64,
    pub actual_decision: Option<PolicyDecision>,
    pub proposed_decision: Option<PolicyDecision>,
    pub plan_digest: Option<String>,
    pub authorization_evidence_digest: Option<String>,
    pub policy_boundary: PolicyBoundaryAssessment,
    pub may_request_apply: bool,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProgressiveAuthorityError {
    #[error("PROGRESSIVE_AUTHORITY_UNSUPPORTED_VERSION")]
    UnsupportedVersion,
    #[error("PROGRESSIVE_AUTHORITY_EMPTY_IDENTIFIER")]
    EmptyIdentifier,
    #[error("PROGRESSIVE_AUTHORITY_INVALID_DIGEST")]
    InvalidDigest,
    #[error("PROGRESSIVE_AUTHORITY_INVALID_MODE_EVIDENCE")]
    InvalidModeEvidence,
    #[error("PROGRESSIVE_AUTHORITY_APPLY_NOT_AUTHORIZED")]
    ApplyNotAuthorized,
    #[error("PROGRESSIVE_AUTHORITY_POLICY_BOUNDARY_NOT_SATISFIED")]
    PolicyBoundaryNotSatisfied,
    #[error("PROGRESSIVE_AUTHORITY_STALE_POLICY_GENERATION")]
    StalePolicyGeneration,
    #[error("PROGRESSIVE_AUTHORITY_UNSUPPORTED_REQUIRED_EXTENSION:{0}")]
    UnsupportedRequiredExtension(String),
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn validate_progressive_authority(
    value: &ProgressiveAuthorityEvidenceV1,
    supported_extensions: &BTreeSet<String>,
) -> Result<(), ProgressiveAuthorityError> {
    if value.schema_version != PROGRESSIVE_AUTHORITY_VERSION {
        return Err(ProgressiveAuthorityError::UnsupportedVersion);
    }
    if [&value.evidence_id, &value.application_id, &value.intent]
        .iter()
        .any(|identifier| identifier.trim().is_empty())
    {
        return Err(ProgressiveAuthorityError::EmptyIdentifier);
    }
    if !valid_digest(&value.fact_snapshot_digest)
        || value
            .plan_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
        || value
            .authorization_evidence_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Err(ProgressiveAuthorityError::InvalidDigest);
    }
    for extension in &value.extensions {
        if !supported_extensions.contains(&extension.id)
            && matches!(
                extension.class,
                ExtensionClass::RequiredUnderstood | ExtensionClass::RequiredSecurityCritical
            )
        {
            return Err(ProgressiveAuthorityError::UnsupportedRequiredExtension(
                extension.id.clone(),
            ));
        }
    }

    match value.mode {
        OperatingMode::Observe => {
            if value.actual_decision.is_none()
                || value.proposed_decision.is_some()
                || value.plan_digest.is_some()
                || value.authorization_evidence_digest.is_some()
                || value.may_request_apply
            {
                return Err(ProgressiveAuthorityError::InvalidModeEvidence);
            }
        }
        OperatingMode::Recommend => {
            if value.actual_decision.is_none()
                || value.proposed_decision.is_none()
                || value.plan_digest.is_some()
                || value.authorization_evidence_digest.is_some()
                || value.may_request_apply
            {
                return Err(ProgressiveAuthorityError::InvalidModeEvidence);
            }
        }
        OperatingMode::Confirm | OperatingMode::AutomaticWithinPolicy => {
            if value.proposed_decision.is_none()
                || value.plan_digest.is_none()
                || value.authorization_evidence_digest.is_none()
                || !value.may_request_apply
            {
                return Err(ProgressiveAuthorityError::ApplyNotAuthorized);
            }
            if value.policy_boundary != PolicyBoundaryAssessment::Satisfied {
                return Err(ProgressiveAuthorityError::PolicyBoundaryNotSatisfied);
            }
        }
    }
    Ok(())
}

pub fn validate_progressive_authority_for_generation(
    value: &ProgressiveAuthorityEvidenceV1,
    current_policy_generation: u64,
    supported_extensions: &BTreeSet<String>,
) -> Result<(), ProgressiveAuthorityError> {
    validate_progressive_authority(value, supported_extensions)?;
    if value.policy_generation != current_policy_generation {
        return Err(ProgressiveAuthorityError::StalePolicyGeneration);
    }
    Ok(())
}
