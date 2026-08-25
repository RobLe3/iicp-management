use iicp_management_core::{
    execution::{ExecutionState, RetryDisposition},
    sandbox::{run_authorized_sandbox, SandboxScenario},
};

#[test]
fn authorized_local_exercise_converges_without_external_activation() {
    let result = run_authorized_sandbox(SandboxScenario::Success, 1_700_000_000).unwrap();
    assert_eq!(result.lifecycle.state, ExecutionState::Converged);
    assert_eq!(result.lifecycle.retry, RetryDisposition::NotNeeded);
    assert_eq!(result.evidence_class, "project_rehearsal");
    assert!(!result.representative);
    assert!(result.local_only);
    assert!(!result.activated_external_state);
}

#[test]
fn verification_failure_is_never_reported_as_success_or_retried() {
    let result =
        run_authorized_sandbox(SandboxScenario::VerificationFailure, 1_700_000_001).unwrap();
    assert_eq!(result.lifecycle.state, ExecutionState::Failed);
    assert_eq!(
        result.lifecycle.retry,
        RetryDisposition::ManualReviewRequired
    );
    assert!(!result.automatic_retry_permitted);
}

#[test]
fn interrupted_execution_observes_state_before_any_retry() {
    let result = run_authorized_sandbox(SandboxScenario::InterruptedResume, 1_700_000_002).unwrap();
    assert_eq!(result.lifecycle.state, ExecutionState::PartiallyConverged);
    assert_eq!(
        result.lifecycle.reason,
        "EXECUTION_EFFECT_OBSERVED_AFTER_RESTART"
    );
    assert!(result.lifecycle.adapter_receipt.is_none());
    assert!(result.lifecycle.verification_receipt.is_some());
    assert!(!result.automatic_retry_permitted);
}
