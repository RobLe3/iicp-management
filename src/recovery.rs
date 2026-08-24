use crate::{
    adapters::{AdapterError, AdapterHost, AdapterOperation, AdapterReceipt},
    apply_gate::{
        authorization_signing_bytes, validate_apply_gate, ApplyAuthorizationEvidenceV1,
        LocalApplyGateV1,
    },
    controller::{ApplyAuthorizationReceiptV1, Controller},
    digest,
    execution::{ApplyLifecycleReceiptV1, ExecutionState},
    progressive_authority::{
        OperatingMode, PolicyBoundaryAssessment, ProgressiveAuthorityEvidenceV1,
    },
    ConvergenceState, PolicyDecision,
};
use serde::{Deserialize, Serialize};

pub const RECOVERY_SCHEMA: &str = "iicp.management-local-recovery.v1";
pub const RECOVERY_EXECUTION_SCHEMA: &str = "iicp.management-local-recovery-execution.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    ExactReversal,
    Compensation,
    Safing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecoveryGateV1 {
    pub schema_version: String,
    pub request: crate::controller::ManagementRequest,
    pub original_gate: LocalApplyGateV1,
    pub original_execution: ApplyLifecycleReceiptV1,
    pub operation: AdapterOperation,
    pub strategy: RecoveryStrategy,
    pub progressive_authority: ProgressiveAuthorityEvidenceV1,
    pub authorization: ApplyAuthorizationEvidenceV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecoveryExecutionV1 {
    pub schema_version: String,
    pub gate: LocalRecoveryGateV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOutcome {
    Reversed,
    Compensated,
    Safed,
    PartiallyRecovered,
    Deferred,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLifecycleReceiptV1 {
    pub schema_version: String,
    pub operation_id: String,
    pub strategy: RecoveryStrategy,
    pub controller_authorization: ApplyAuthorizationReceiptV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_receipt: Option<AdapterReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_receipt: Option<AdapterReceipt>,
    pub outcome: RecoveryOutcome,
    pub reason: String,
    pub safe_next_action: String,
}

pub fn validate_recovery_gate(value: &LocalRecoveryGateV1, now: u64) -> Result<(), String> {
    validate_apply_gate(
        &value.original_gate,
        value.original_gate.authorization.issued_at,
    )
    .map_err(|_| "RECOVERY_ORIGINAL_GATE_INVALID")?;
    let original_planned = value
        .original_gate
        .plan
        .operations
        .iter()
        .find(|item| item.operation_id == value.original_gate.operation.operation_id)
        .ok_or("RECOVERY_ORIGINAL_PLAN_INVALID")?;
    let original_adapter = value
        .original_execution
        .adapter_receipt
        .as_ref()
        .ok_or("RECOVERY_ORIGINAL_EXECUTION_UNPROVEN")?;
    let recovery_context_digest = digest(&(&value.original_gate, &value.original_execution))
        .map_err(|_| "RECOVERY_ORIGINAL_CONTEXT_INVALID")?;
    let expected_action = match value.strategy {
        RecoveryStrategy::ExactReversal => "rollback",
        RecoveryStrategy::Compensation => "compensate",
        RecoveryStrategy::Safing => "safe",
    };
    if value.schema_version != RECOVERY_SCHEMA
        || value.request.action != expected_action
        || value.operation.action != expected_action
        || value.request.request_id != value.operation.operation_id
        || value.request.resource_ids != vec![value.operation.target_id.clone()]
        || value.request.payload_digest != value.operation.desired_digest
        || value.request.plan_digest != value.operation.plan_digest
        || value.request.plan_digest != recovery_context_digest
        || value.operation.target_id != value.original_gate.operation.target_id
        || value.operation.capability != value.original_gate.operation.capability
        || value.operation.related_operation_id.as_deref()
            != Some(value.original_gate.operation.operation_id.as_str())
        || value.operation.expected_generation != original_adapter.generation
        || value.operation.desired_digest != original_planned.before_digest
        || value.original_execution.state != ExecutionState::Converged
        || value.authorization.operation_digest
            != digest(&value.operation).map_err(|_| "RECOVERY_BINDING_INVALID")?
        || value.authorization.plan_digest != value.request.plan_digest
        || value.authorization.issuer_id != value.request.issuer_id
        || value.authorization.audience != value.request.audience
        || value.authorization.administrative_domain != value.request.administrative_domain
        || value.authorization.mode != value.progressive_authority.mode
        || value.authorization.policy_generation != value.progressive_authority.policy_generation
        || value.authorization.fact_snapshot_digest
            != value.progressive_authority.fact_snapshot_digest
        || value.authorization.policy_boundary != PolicyBoundaryAssessment::Satisfied
        || value.authorization.proposed_decision != PolicyDecision::Allow
        || value.progressive_authority.proposed_decision != Some(PolicyDecision::Allow)
        || value.progressive_authority.plan_digest.as_deref()
            != Some(value.request.plan_digest.as_str())
        || value
            .progressive_authority
            .authorization_evidence_digest
            .as_deref()
            != Some(
                digest(&value.authorization)
                    .map_err(|_| "RECOVERY_BINDING_INVALID")?
                    .as_str(),
            )
        || value.authorization.issued_at > now
        || now > value.authorization.expires_at
        || value.authorization.expires_at > value.request.expires_at
        || value.operation.expires_at > value.request.expires_at
    {
        return Err("RECOVERY_BINDING_INVALID".into());
    }
    if !matches!(
        value.progressive_authority.mode,
        OperatingMode::Confirm | OperatingMode::AutomaticWithinPolicy
    ) {
        return Err("RECOVERY_MODE_NOT_AUTHORIZED".into());
    }
    Ok(())
}

pub fn execute_recovery(
    controller: &Controller,
    host: &mut AdapterHost,
    gate: &LocalRecoveryGateV1,
    now: u64,
) -> Result<RecoveryLifecycleReceiptV1, String> {
    validate_recovery_gate(gate, now)?;
    let (authorization, operation) = controller
        .resume_authorized_recovery(gate, now)
        .map_err(|error| error.to_string())?;
    if gate.strategy != RecoveryStrategy::ExactReversal {
        return Ok(RecoveryLifecycleReceiptV1 {
            schema_version: RECOVERY_SCHEMA.into(),
            operation_id: gate.operation.operation_id.clone(),
            strategy: gate.strategy.clone(),
            controller_authorization: authorization,
            adapter_receipt: None,
            verification_receipt: None,
            outcome: RecoveryOutcome::Failed,
            reason: "RECOVERY_STRATEGY_UNSUPPORTED_BY_ADAPTER".into(),
            safe_next_action: match gate.strategy {
                RecoveryStrategy::Compensation => "DEFINE_ADAPTER_COMPENSATION".into(),
                RecoveryStrategy::Safing => "DEFINE_ADAPTER_SAFE_STATE".into(),
                _ => unreachable!(),
            },
        });
    }
    let recovered = host.execute(&operation, now);
    let verified = host.verify_authorized(&operation);
    let adapter_receipt = recovered.as_ref().ok().cloned();
    let verification_receipt = verified.as_ref().ok().cloned();
    let (outcome, reason, next) = match (&recovered, &verified) {
        (Ok(adapter), Ok(verify))
            if adapter.state == ConvergenceState::Converged
                && verify.state == ConvergenceState::Converged
                && verify.result_digest == gate.operation.desired_digest =>
        {
            (
                RecoveryOutcome::Reversed,
                "RECOVERY_VERIFIED_REVERSED",
                "NONE",
            )
        }
        (Ok(_), Ok(_)) => (
            RecoveryOutcome::PartiallyRecovered,
            "RECOVERY_NOT_FULLY_CONVERGED",
            "KEEP_TARGET_SAFED_AND_REVIEW",
        ),
        (Err(AdapterError::Timeout | AdapterError::OutcomeUnknown | AdapterError::Io), _) => (
            RecoveryOutcome::Deferred,
            "RECOVERY_OUTCOME_UNKNOWN",
            "OBSERVE_BEFORE_RETRY",
        ),
        (Ok(_), Err(_)) => (
            RecoveryOutcome::PartiallyRecovered,
            "RECOVERY_VERIFICATION_UNAVAILABLE",
            "OBSERVE_AND_REVIEW",
        ),
        (Err(_), _) => (
            RecoveryOutcome::Failed,
            "RECOVERY_REJECTED_BY_ADAPTER",
            "KEEP_CURRENT_STATE_AND_REPLAN",
        ),
    };
    Ok(RecoveryLifecycleReceiptV1 {
        schema_version: RECOVERY_SCHEMA.into(),
        operation_id: gate.operation.operation_id.clone(),
        strategy: gate.strategy.clone(),
        controller_authorization: authorization,
        adapter_receipt,
        verification_receipt,
        outcome,
        reason: reason.into(),
        safe_next_action: next.into(),
    })
}

pub fn execute_recovery_request(
    controller: &Controller,
    host: &mut AdapterHost,
    request: &LocalRecoveryExecutionV1,
    now: u64,
) -> Result<RecoveryLifecycleReceiptV1, String> {
    if request.schema_version != RECOVERY_EXECUTION_SCHEMA {
        return Err("RECOVERY_EXECUTION_SCHEMA_INVALID".into());
    }
    execute_recovery(controller, host, &request.gate, now)
}

pub fn authorization_bytes(value: &ApplyAuthorizationEvidenceV1) -> Result<Vec<u8>, String> {
    authorization_signing_bytes(value).map_err(|_| "RECOVERY_AUTHORIZATION_INVALID".into())
}
