use crate::{
    adapters::AdapterOperation,
    controller::{ManagementRequest, SIGNATURE_PROFILE},
    digest,
    progressive_authority::{
        validate_progressive_authority_for_generation, OperatingMode, PolicyBoundaryAssessment,
        ProgressiveAuthorityEvidenceV1,
    },
    Plan, PolicyDecision,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const APPLY_GATE_SCHEMA: &str = "iicp.management-apply-gate.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyAuthorizationEvidenceV1 {
    pub schema_version: String,
    pub authorization_id: String,
    pub issuer_id: String,
    pub audience: String,
    pub administrative_domain: String,
    pub mode: OperatingMode,
    pub plan_digest: String,
    pub operation_digest: String,
    pub policy_generation: u64,
    pub fact_snapshot_digest: String,
    pub policy_boundary: PolicyBoundaryAssessment,
    pub proposed_decision: PolicyDecision,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_profile: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalApplyGateV1 {
    pub schema_version: String,
    pub request: ManagementRequest,
    pub plan: Plan,
    pub operation: AdapterOperation,
    pub progressive_authority: ProgressiveAuthorityEvidenceV1,
    pub authorization: ApplyAuthorizationEvidenceV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplyPreviewV1 {
    pub schema_version: String,
    pub operation_id: String,
    pub target_id: String,
    pub action: String,
    pub before_digest: String,
    pub after_digest: String,
    pub plan_generation: u64,
    pub controller_generation: u64,
    pub policy_generation: u64,
    pub expires_at: u64,
    pub mode: OperatingMode,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApplyGateError {
    #[error("APPLY_GATE_INVALID_BINDING")]
    InvalidBinding,
    #[error("APPLY_GATE_MODE_NOT_AUTHORIZED")]
    ModeNotAuthorized,
    #[error("APPLY_GATE_AUTHORIZATION_EXPIRED")]
    AuthorizationExpired,
    #[error("APPLY_GATE_PROGRESSIVE_AUTHORITY_INVALID")]
    ProgressiveAuthorityInvalid,
}

pub fn authorization_signing_bytes(
    value: &ApplyAuthorizationEvidenceV1,
) -> Result<Vec<u8>, ApplyGateError> {
    let mut value = serde_json::to_value(value).map_err(|_| ApplyGateError::InvalidBinding)?;
    value
        .as_object_mut()
        .ok_or(ApplyGateError::InvalidBinding)?
        .remove("signature");
    serde_jcs::to_vec(&value).map_err(|_| ApplyGateError::InvalidBinding)
}

pub fn validate_apply_gate(value: &LocalApplyGateV1, now: u64) -> Result<(), ApplyGateError> {
    if value.schema_version != APPLY_GATE_SCHEMA
        || value.authorization.schema_version != "1"
        || value.authorization.signature_profile != SIGNATURE_PROFILE
        || value.request.action != "apply"
        || value.request.request_id != value.operation.operation_id
        || value.request.resource_ids != vec![value.operation.target_id.clone()]
        || value.request.payload_digest != value.operation.desired_digest
        || value.request.plan_digest
            != digest(&value.plan).map_err(|_| ApplyGateError::InvalidBinding)?
        || value.operation.plan_digest != value.request.plan_digest
        || value.operation.desired_digest
            != digest(&value.operation.desired).map_err(|_| ApplyGateError::InvalidBinding)?
        || value.plan.target_generation != value.request.expected_generation
        || value.operation.expires_at > value.request.expires_at
        || value.authorization.expires_at > value.request.expires_at
        || value.authorization.issued_at > now
        || now > value.authorization.expires_at
    {
        return Err(ApplyGateError::InvalidBinding);
    }
    let planned = value
        .plan
        .operations
        .iter()
        .find(|operation| operation.operation_id == value.operation.operation_id)
        .ok_or(ApplyGateError::InvalidBinding)?;
    if planned.resource_id != value.operation.target_id
        || planned.after_digest != value.operation.desired_digest
        || planned.target_generation != value.operation.expected_generation
        || value.authorization.issuer_id != value.request.issuer_id
        || value.authorization.audience != value.request.audience
        || value.authorization.administrative_domain != value.request.administrative_domain
        || value.authorization.plan_digest != value.request.plan_digest
        || value.authorization.operation_digest
            != digest(&value.operation).map_err(|_| ApplyGateError::InvalidBinding)?
        || value.authorization.policy_generation != value.progressive_authority.policy_generation
        || value.authorization.fact_snapshot_digest
            != value.progressive_authority.fact_snapshot_digest
        || value.authorization.policy_boundary != value.progressive_authority.policy_boundary
        || value.authorization.proposed_decision
            != value
                .progressive_authority
                .proposed_decision
                .clone()
                .ok_or(ApplyGateError::InvalidBinding)?
        || value.authorization.mode != value.progressive_authority.mode
        || value.progressive_authority.plan_digest.as_deref()
            != Some(value.request.plan_digest.as_str())
        || value
            .progressive_authority
            .authorization_evidence_digest
            .as_deref()
            != Some(
                digest(&value.authorization)
                    .map_err(|_| ApplyGateError::InvalidBinding)?
                    .as_str(),
            )
    {
        return Err(ApplyGateError::InvalidBinding);
    }
    if !matches!(
        value.progressive_authority.mode,
        OperatingMode::Confirm | OperatingMode::AutomaticWithinPolicy
    ) {
        return Err(ApplyGateError::ModeNotAuthorized);
    }
    validate_progressive_authority_for_generation(
        &value.progressive_authority,
        value.authorization.policy_generation,
        &BTreeSet::new(),
    )
    .map_err(|_| ApplyGateError::ProgressiveAuthorityInvalid)?;
    if value.authorization.policy_boundary != PolicyBoundaryAssessment::Satisfied
        || value.authorization.proposed_decision != PolicyDecision::Allow
    {
        return Err(ApplyGateError::ProgressiveAuthorityInvalid);
    }
    Ok(())
}

pub fn preview_apply(value: &LocalApplyGateV1, now: u64) -> Result<ApplyPreviewV1, ApplyGateError> {
    validate_apply_gate(value, now)?;
    let planned = value
        .plan
        .operations
        .iter()
        .find(|operation| operation.operation_id == value.operation.operation_id)
        .ok_or(ApplyGateError::InvalidBinding)?;
    Ok(ApplyPreviewV1 {
        schema_version: APPLY_GATE_SCHEMA.into(),
        operation_id: value.operation.operation_id.clone(),
        target_id: value.operation.target_id.clone(),
        action: value.operation.action.clone(),
        before_digest: planned.before_digest.clone(),
        after_digest: planned.after_digest.clone(),
        plan_generation: value.plan.target_generation,
        controller_generation: value.request.expected_generation,
        policy_generation: value.progressive_authority.policy_generation,
        expires_at: value.request.expires_at,
        mode: value.progressive_authority.mode.clone(),
    })
}
