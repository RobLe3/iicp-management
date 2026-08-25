use crate::{
    adapters::{AdapterError, AdapterHost, AdapterReceipt},
    apply_gate::LocalApplyGateV1,
    controller::{ApplyAuthorizationReceiptV1, Controller, DecisionState},
    ConvergenceState,
};
use serde::{Deserialize, Serialize};

pub const EXECUTION_SCHEMA: &str = "iicp.management-local-execution.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalApplyExecutionV1 {
    pub schema_version: String,
    pub gate: LocalApplyGateV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Converged,
    PartiallyConverged,
    Deferred,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    NotNeeded,
    ObserveBeforeRetryCompleted,
    ManualReviewRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplyLifecycleReceiptV1 {
    pub schema_version: String,
    pub operation_id: String,
    pub controller_authorization: ApplyAuthorizationReceiptV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_receipt: Option<AdapterReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_receipt: Option<AdapterReceipt>,
    pub state: ExecutionState,
    pub reason: String,
    pub retry: RetryDisposition,
}

impl ApplyLifecycleReceiptV1 {
    pub fn failure(operation_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            schema_version: EXECUTION_SCHEMA.into(),
            operation_id: operation_id.into(),
            controller_authorization: ApplyAuthorizationReceiptV1::failure(
                "",
                DecisionState::Rejected,
                "EXECUTION_NOT_AUTHORIZED",
                None,
            ),
            adapter_receipt: None,
            verification_receipt: None,
            state: ExecutionState::Failed,
            reason: reason.into(),
            retry: RetryDisposition::ManualReviewRequired,
        }
    }
}

pub fn execute_authorized(
    controller: &Controller,
    host: &mut AdapterHost,
    execution: &LocalApplyExecutionV1,
    now: u64,
) -> Result<ApplyLifecycleReceiptV1, String> {
    if execution.schema_version != EXECUTION_SCHEMA {
        return Err("EXECUTION_SCHEMA_INVALID".into());
    }
    let (authorization, operation) = controller
        .resume_authorized_apply(&execution.gate, now)
        .map_err(|error| error.to_string())?;
    let operation_digest =
        crate::digest(&execution.gate.operation).map_err(|error| error.to_string())?;
    if let Some(record) = controller
        .execution_journal(&execution.gate.request.request_id, &operation_digest)
        .map_err(|error| error.to_string())?
    {
        if matches!(record.phase.as_str(), "complete" | "verified") {
            if let Some(json) = record.lifecycle_receipt_json {
                let receipt: ApplyLifecycleReceiptV1 =
                    serde_json::from_str(&json).map_err(|_| "EXECUTION_JOURNAL_INVALID")?;
                if record.phase == "verified" {
                    controller
                        .record_execution_phase(
                            &execution.gate.request.request_id,
                            &operation_digest,
                            "complete",
                            None,
                            Some(&json),
                            now,
                        )
                        .map_err(|error| error.to_string())?;
                }
                return Ok(receipt);
            }
        }
        if record.phase == "started" {
            let verified = host.verify_authorized(&operation);
            let (state, reason, retry) = match &verified {
                Ok(receipt)
                    if receipt.state == ConvergenceState::Converged
                        && receipt.result_digest == execution.gate.operation.desired_digest =>
                {
                    (
                        ExecutionState::PartiallyConverged,
                        "EXECUTION_EFFECT_OBSERVED_AFTER_RESTART",
                        RetryDisposition::ManualReviewRequired,
                    )
                }
                Ok(_) => (
                    ExecutionState::Deferred,
                    "EXECUTION_RESTART_OBSERVATION_MISMATCH",
                    RetryDisposition::ManualReviewRequired,
                ),
                Err(_) => (
                    ExecutionState::Deferred,
                    "EXECUTION_RESTART_OBSERVATION_UNAVAILABLE",
                    RetryDisposition::ManualReviewRequired,
                ),
            };
            let receipt = ApplyLifecycleReceiptV1 {
                schema_version: EXECUTION_SCHEMA.into(),
                operation_id: execution.gate.operation.operation_id.clone(),
                controller_authorization: authorization,
                adapter_receipt: None,
                verification_receipt: verified.ok(),
                state,
                reason: reason.into(),
                retry,
            };
            persist_complete(controller, execution, &operation_digest, &receipt, now)?;
            return Ok(receipt);
        }
        if record.phase == "adapter_reported" {
            let applied: AdapterReceipt = serde_json::from_str(
                record
                    .adapter_receipt_json
                    .as_deref()
                    .ok_or("EXECUTION_JOURNAL_INVALID")?,
            )
            .map_err(|_| "EXECUTION_JOURNAL_INVALID")?;
            let verified = host.verify_authorized(&operation);
            let receipt = lifecycle(authorization, execution, Ok(applied), verified);
            persist_verified_and_complete(controller, execution, &operation_digest, &receipt, now)?;
            return Ok(receipt);
        }
    }
    controller
        .record_execution_phase(
            &execution.gate.request.request_id,
            &operation_digest,
            "started",
            None,
            None,
            now,
        )
        .map_err(|error| error.to_string())?;
    let applied = host.execute(&operation, now);
    if let Ok(receipt) = &applied {
        let json = serde_json::to_string(receipt).map_err(|_| "EXECUTION_RECEIPT_INVALID")?;
        controller
            .record_execution_phase(
                &execution.gate.request.request_id,
                &operation_digest,
                "adapter_reported",
                Some(&json),
                None,
                now,
            )
            .map_err(|error| error.to_string())?;
    }
    // Verification is deliberately independent and is attempted even when the
    // adapter reports a timeout or unknown outcome. Nothing here retries apply.
    let verified = host.verify_authorized(&operation);
    let receipt = lifecycle(authorization, execution, applied, verified);
    persist_verified_and_complete(controller, execution, &operation_digest, &receipt, now)?;
    Ok(receipt)
}

fn lifecycle(
    authorization: ApplyAuthorizationReceiptV1,
    execution: &LocalApplyExecutionV1,
    applied: Result<AdapterReceipt, AdapterError>,
    verified: Result<AdapterReceipt, AdapterError>,
) -> ApplyLifecycleReceiptV1 {
    let adapter_receipt = applied.as_ref().ok().cloned();
    let verification_receipt = verified.as_ref().ok().cloned();
    let (state, reason, retry) = match (&applied, &verified) {
        (Ok(apply), Ok(verify))
            if apply.state == ConvergenceState::Converged
                && verify.state == ConvergenceState::Converged
                && verify.result_digest == execution.gate.operation.desired_digest =>
        {
            (
                ExecutionState::Converged,
                "EXECUTION_VERIFIED",
                RetryDisposition::NotNeeded,
            )
        }
        (Ok(_), Ok(verify)) if verify.state == ConvergenceState::Failed => (
            ExecutionState::Failed,
            "EXECUTION_VERIFIED_FAILED",
            RetryDisposition::ManualReviewRequired,
        ),
        (Ok(_), Ok(_)) => (
            ExecutionState::PartiallyConverged,
            "EXECUTION_NOT_FULLY_CONVERGED",
            RetryDisposition::ManualReviewRequired,
        ),
        (Err(AdapterError::Timeout | AdapterError::OutcomeUnknown | AdapterError::Io), Ok(_)) => (
            ExecutionState::Deferred,
            "EXECUTION_OUTCOME_OBSERVED_BEFORE_RETRY",
            RetryDisposition::ObserveBeforeRetryCompleted,
        ),
        (Err(AdapterError::Timeout | AdapterError::OutcomeUnknown | AdapterError::Io), Err(_)) => (
            ExecutionState::Deferred,
            "EXECUTION_OUTCOME_UNKNOWN",
            RetryDisposition::ManualReviewRequired,
        ),
        (Ok(_), Err(_)) => (
            ExecutionState::PartiallyConverged,
            "EXECUTION_VERIFICATION_UNAVAILABLE",
            RetryDisposition::ManualReviewRequired,
        ),
        (Err(_), _) => (
            ExecutionState::Failed,
            "EXECUTION_REJECTED_BY_ADAPTER",
            RetryDisposition::ManualReviewRequired,
        ),
    };
    ApplyLifecycleReceiptV1 {
        schema_version: EXECUTION_SCHEMA.into(),
        operation_id: execution.gate.operation.operation_id.clone(),
        controller_authorization: authorization,
        adapter_receipt,
        verification_receipt,
        state,
        reason: reason.into(),
        retry,
    }
}

fn persist_verified_and_complete(
    controller: &Controller,
    execution: &LocalApplyExecutionV1,
    operation_digest: &str,
    receipt: &ApplyLifecycleReceiptV1,
    now: u64,
) -> Result<(), String> {
    let json = serde_json::to_string(receipt).map_err(|_| "EXECUTION_RECEIPT_INVALID")?;
    controller
        .record_execution_phase(
            &execution.gate.request.request_id,
            operation_digest,
            "verified",
            None,
            Some(&json),
            now,
        )
        .map_err(|error| error.to_string())?;
    controller
        .record_execution_phase(
            &execution.gate.request.request_id,
            operation_digest,
            "complete",
            None,
            Some(&json),
            now,
        )
        .map_err(|error| error.to_string())
}

fn persist_complete(
    controller: &Controller,
    execution: &LocalApplyExecutionV1,
    operation_digest: &str,
    receipt: &ApplyLifecycleReceiptV1,
    now: u64,
) -> Result<(), String> {
    let json = serde_json::to_string(receipt).map_err(|_| "EXECUTION_RECEIPT_INVALID")?;
    controller
        .record_execution_phase(
            &execution.gate.request.request_id,
            operation_digest,
            "complete",
            None,
            Some(&json),
            now,
        )
        .map_err(|error| error.to_string())
}
