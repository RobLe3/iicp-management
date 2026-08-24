use crate::{
    adapters::{
        validate_adapter_inspection, AdapterInspectionV1, AdapterOperation,
        AuthorizedAdapterOperation,
    },
    apply_gate::{
        authorization_signing_bytes, validate_apply_gate, LocalApplyGateV1, APPLY_GATE_SCHEMA,
    },
    digest,
    recovery::{validate_recovery_gate, LocalRecoveryGateV1},
    ManagementError, Plan,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const SIGNATURE_PROFILE: &str = "ed25519-jcs-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementRequest {
    pub schema_version: String,
    pub request_id: String,
    pub issuer_id: String,
    pub audience: String,
    pub administrative_domain: String,
    pub action: String,
    pub resource_ids: Vec<String>,
    pub payload_digest: String,
    pub plan_digest: String,
    pub expected_generation: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub signature_profile: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionState {
    Accepted,
    Rejected,
    Deferred,
    Partial,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerReceipt {
    pub request_id: String,
    pub decision: DecisionState,
    pub reason: String,
    pub generation: u64,
}

pub const PLAN_SUBMISSION_SCHEMA: &str = "iicp.management-plan-submission.v1";
pub const PLAN_ACCEPT_ACTION: &str = "accept_plan";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPlanSubmissionV1 {
    pub schema_version: String,
    pub request: ManagementRequest,
    pub plan: Plan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanSubmissionReceiptV1 {
    pub schema_version: String,
    pub request_id: String,
    pub decision: DecisionState,
    pub reason: String,
    pub controller_generation: Option<u64>,
    pub target_effect: String,
    pub convergence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplyAuthorizationReceiptV1 {
    pub schema_version: String,
    pub request_id: String,
    pub decision: DecisionState,
    pub reason: String,
    pub controller_generation: Option<u64>,
    pub operation_digest: String,
    pub authority_context_digest: String,
    pub target_effect: String,
    pub convergence: String,
}

impl ApplyAuthorizationReceiptV1 {
    fn from_controller(
        receipt: ControllerReceipt,
        operation_digest: String,
        authority_context_digest: String,
    ) -> Self {
        Self {
            schema_version: APPLY_GATE_SCHEMA.into(),
            request_id: receipt.request_id,
            decision: receipt.decision,
            reason: receipt.reason,
            controller_generation: Some(receipt.generation),
            operation_digest,
            authority_context_digest,
            target_effect: "not_attempted".into(),
            convergence: "not_evaluated".into(),
        }
    }

    pub fn failure(
        request_id: impl Into<String>,
        decision: DecisionState,
        reason: impl Into<String>,
        generation: Option<u64>,
    ) -> Self {
        Self {
            schema_version: APPLY_GATE_SCHEMA.into(),
            request_id: request_id.into(),
            decision,
            reason: reason.into(),
            controller_generation: generation,
            operation_digest: String::new(),
            authority_context_digest: String::new(),
            target_effect: "not_attempted".into(),
            convergence: "not_evaluated".into(),
        }
    }
}

impl PlanSubmissionReceiptV1 {
    pub fn from_controller(receipt: ControllerReceipt) -> Self {
        Self {
            schema_version: PLAN_SUBMISSION_SCHEMA.into(),
            request_id: receipt.request_id,
            decision: receipt.decision,
            reason: receipt.reason,
            controller_generation: Some(receipt.generation),
            target_effect: "not_attempted".into(),
            convergence: "not_evaluated".into(),
        }
    }

    pub fn failure(
        request_id: impl Into<String>,
        decision: DecisionState,
        reason: impl Into<String>,
        generation: Option<u64>,
    ) -> Self {
        Self {
            schema_version: PLAN_SUBMISSION_SCHEMA.into(),
            request_id: request_id.into(),
            decision,
            reason: reason.into(),
            controller_generation: generation,
            target_effect: "not_attempted".into(),
            convergence: "not_evaluated".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    pub request_id: String,
    pub decision: DecisionState,
    pub reason: String,
    pub generation: u64,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerSnapshot {
    pub schema_version: String,
    pub evidence_class: String,
    pub authorizes_mutation: bool,
    pub generation: u64,
    pub recent_decisions: Vec<DecisionRecord>,
    pub adapter_capabilities: Vec<String>,
    pub target_state: String,
    pub accepted_state: String,
    pub observed_state: String,
    pub effective_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_inspection: Option<AdapterInspectionV1>,
}

pub fn attach_adapter_inspection(
    mut snapshot: ControllerSnapshot,
    inspection: AdapterInspectionV1,
    now: u64,
) -> Result<ControllerSnapshot, ControllerError> {
    validate_adapter_inspection(&inspection, &BTreeSet::new(), now, 60)
        .map_err(|_| ControllerError::Invalid("adapter_inspection"))?;
    snapshot.adapter_capabilities = inspection
        .entries
        .iter()
        .flat_map(|entry| entry.advertised_capabilities.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let states = inspection
        .entries
        .iter()
        .filter_map(|entry| entry.convergence_state.clone())
        .collect::<Vec<_>>();
    snapshot.observed_state = if inspection.entries.is_empty() {
        "no_registered_adapters"
    } else if inspection
        .entries
        .iter()
        .any(|entry| entry.reason_code == "ADAPTER_OBSERVATION_FAILED")
    {
        "observation_failed"
    } else if states.len() != inspection.entries.len() {
        "observed_without_convergence_receipt"
    } else if states
        .iter()
        .all(|state| *state == crate::ConvergenceState::Converged)
    {
        "converged"
    } else if states
        .iter()
        .all(|state| *state == crate::ConvergenceState::Failed)
    {
        "failed"
    } else {
        "partially_converged"
    }
    .into();
    snapshot.effective_state = if inspection.entries.iter().any(|entry| {
        entry
            .observed_generation
            .is_some_and(|generation| generation != snapshot.generation)
    }) {
        "generation_mismatch".into()
    } else {
        snapshot.observed_state.clone()
    };
    snapshot.target_state = snapshot.observed_state.clone();
    snapshot.adapter_inspection = Some(inspection);
    Ok(snapshot)
}

pub fn inspect_controller_database(
    path: &Path,
    limit: u64,
) -> Result<ControllerSnapshot, ControllerError> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| ControllerError::Storage)?;
    let generation = connection
        .query_row("SELECT generation FROM state WHERE id=1", [], |row| {
            row.get(0)
        })
        .map_err(|_| ControllerError::Storage)?;
    let mut statement = connection
        .prepare("SELECT request_id,decision,reason,generation,recorded_at FROM decision_events ORDER BY id DESC LIMIT ?1")
        .map_err(|_| ControllerError::Storage)?;
    let rows = statement
        .query_map([limit.min(100)], |row| {
            let decision: String = row.get(1)?;
            Ok(DecisionRecord {
                request_id: row.get(0)?,
                decision: match decision.as_str() {
                    "accepted" => DecisionState::Accepted,
                    "rejected" => DecisionState::Rejected,
                    "deferred" => DecisionState::Deferred,
                    "partial" => DecisionState::Partial,
                    _ => DecisionState::Failed,
                },
                reason: row.get(2)?,
                generation: row.get(3)?,
                recorded_at: row.get(4)?,
            })
        })
        .map_err(|_| ControllerError::Storage)?;
    let recent_decisions = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ControllerError::Storage)?;
    Ok(ControllerSnapshot {
        schema_version: "1".into(),
        evidence_class: "local_controller_snapshot".into(),
        authorizes_mutation: false,
        generation,
        recent_decisions,
        adapter_capabilities: Vec::new(),
        target_state: "not_reported_by_controller_store".into(),
        accepted_state: format!("generation:{generation}"),
        observed_state: "not_reported".into(),
        effective_state: "not_computed".into(),
        adapter_inspection: None,
    })
}

#[derive(Debug, Clone)]
pub struct ControllerPolicy {
    pub audience: String,
    pub domain: String,
    pub allowed_actions: BTreeSet<String>,
    pub revocation_checkpoint: u64,
    pub max_checkpoint_age: u64,
    pub high_impact_actions: BTreeSet<String>,
    pub max_decision_events: u64,
}

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("REQUEST_INVALID:{0}")]
    Invalid(&'static str),
    #[error("REQUEST_REPLAY")]
    Replay,
    #[error("REQUEST_SIGNATURE_INVALID")]
    Signature,
    #[error("REQUEST_GENERATION_CONFLICT")]
    Generation,
    #[error("REQUEST_POLICY_DENIED")]
    Policy,
    #[error("STORAGE_ERROR")]
    Storage,
    #[error("REQUEST_ADAPTER_BINDING_INVALID")]
    AdapterBinding,
    #[error("REQUEST_APPLY_GATE_INVALID")]
    ApplyGate,
    #[error(transparent)]
    Core(#[from] ManagementError),
}

pub struct Controller {
    connection: Connection,
    policy: ControllerPolicy,
    verifying_key: VerifyingKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionJournalRecord {
    pub phase: String,
    pub adapter_receipt_json: Option<String>,
    pub lifecycle_receipt_json: Option<String>,
}

#[derive(Debug, Clone)]
struct ApplyAuthorizationBinding {
    operation_digest: String,
    authority_context_digest: String,
}

impl Controller {
    pub fn open(
        path: &Path,
        policy: ControllerPolicy,
        key: [u8; 32],
    ) -> Result<Self, ControllerError> {
        let connection = Connection::open(path).map_err(|_| ControllerError::Storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| ControllerError::Storage)?;
        }
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL); INSERT OR IGNORE INTO state VALUES(1,0); CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL, consumed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS decisions(request_id TEXT PRIMARY KEY, decision TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS decision_events(id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL, recorded_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS apply_authorizations(request_id TEXT PRIMARY KEY, operation_digest TEXT NOT NULL, authority_context_digest TEXT NOT NULL, accepted_generation INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS execution_journal(request_id TEXT NOT NULL, operation_digest TEXT NOT NULL, phase TEXT NOT NULL, adapter_receipt_json TEXT, lifecycle_receipt_json TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY(request_id,operation_digest));").map_err(|_|ControllerError::Storage)?;
        Ok(Self {
            connection,
            policy,
            verifying_key: VerifyingKey::from_bytes(&key)
                .map_err(|_| ControllerError::Signature)?,
        })
    }
    pub fn generation(&self) -> Result<u64, ControllerError> {
        self.connection
            .query_row("SELECT generation FROM state WHERE id=1", [], |r| r.get(0))
            .map_err(|_| ControllerError::Storage)
    }
    pub fn execution_journal(
        &self,
        request_id: &str,
        operation_digest: &str,
    ) -> Result<Option<ExecutionJournalRecord>, ControllerError> {
        self.connection.query_row(
            "SELECT phase,adapter_receipt_json,lifecycle_receipt_json FROM execution_journal WHERE request_id=?1 AND operation_digest=?2",
            params![request_id, operation_digest],
            |row| Ok(ExecutionJournalRecord { phase: row.get(0)?, adapter_receipt_json: row.get(1)?, lifecycle_receipt_json: row.get(2)? }),
        ).optional().map_err(|_| ControllerError::Storage)
    }
    pub fn record_execution_phase(
        &self,
        request_id: &str,
        operation_digest: &str,
        phase: &str,
        adapter_receipt_json: Option<&str>,
        lifecycle_receipt_json: Option<&str>,
        now: u64,
    ) -> Result<(), ControllerError> {
        if !matches!(
            phase,
            "started" | "adapter_reported" | "verified" | "complete"
        ) {
            return Err(ControllerError::Invalid("execution_phase"));
        }
        self.connection.execute(
            "INSERT INTO execution_journal(request_id,operation_digest,phase,adapter_receipt_json,lifecycle_receipt_json,updated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(request_id,operation_digest) DO UPDATE SET phase=excluded.phase,adapter_receipt_json=COALESCE(excluded.adapter_receipt_json,execution_journal.adapter_receipt_json),lifecycle_receipt_json=COALESCE(excluded.lifecycle_receipt_json,execution_journal.lifecycle_receipt_json),updated_at=excluded.updated_at",
            params![request_id, operation_digest, phase, adapter_receipt_json, lifecycle_receipt_json, now],
        ).map_err(|_| ControllerError::Storage)?;
        Ok(())
    }
    fn signing_bytes(request: &ManagementRequest) -> Result<Vec<u8>, ControllerError> {
        let mut value =
            serde_json::to_value(request).map_err(|_| ControllerError::Invalid("serialization"))?;
        value.as_object_mut().unwrap().remove("signature");
        serde_jcs::to_vec(&value).map_err(|_| ControllerError::Invalid("serialization"))
    }
    fn validate_text(value: &str, maximum: usize) -> Result<(), ControllerError> {
        if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
            return Err(ControllerError::Invalid("bounded_text"));
        }
        Ok(())
    }
    fn record_rejection(
        &self,
        request_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<(), ControllerError> {
        let generation = self.generation()?;
        self.connection
            .execute(
                "INSERT INTO decision_events(request_id,decision,reason,generation,recorded_at) VALUES(?1,'rejected',?2,?3,?4)",
                params![request_id, reason, generation, now],
            )
            .map_err(|_| ControllerError::Storage)?;
        self.prune_decision_events()?;
        Ok(())
    }
    fn prune_decision_events(&self) -> Result<(), ControllerError> {
        self.connection.execute(
            "DELETE FROM decision_events WHERE id NOT IN (SELECT id FROM decision_events ORDER BY id DESC LIMIT ?1)",
            [self.policy.max_decision_events.max(1)],
        ).map_err(|_| ControllerError::Storage)?;
        Ok(())
    }
    pub fn record_outcome(
        &self,
        request_id: &str,
        decision: DecisionState,
        reason: &str,
        expected_generation: u64,
        now: u64,
    ) -> Result<ControllerReceipt, ControllerError> {
        Self::validate_text(request_id, 128)?;
        Self::validate_text(reason, 256)?;
        if !matches!(
            decision,
            DecisionState::Deferred | DecisionState::Partial | DecisionState::Failed
        ) {
            return Err(ControllerError::Invalid("outcome"));
        }
        let generation = self.generation()?;
        if generation != expected_generation {
            return Err(ControllerError::Generation);
        }
        let name = match decision {
            DecisionState::Deferred => "deferred",
            DecisionState::Partial => "partial",
            DecisionState::Failed => "failed",
            _ => unreachable!(),
        };
        let changed = self
            .connection
            .execute(
                "UPDATE decisions SET decision=?2,reason=?3 WHERE request_id=?1 AND generation=?4",
                params![request_id, name, reason, generation],
            )
            .map_err(|_| ControllerError::Storage)?;
        if changed != 1 {
            return Err(ControllerError::Invalid("unknown_request"));
        }
        self.connection.execute(
            "INSERT INTO decision_events(request_id,decision,reason,generation,recorded_at) VALUES(?1,?2,?3,?4,?5)",
            params![request_id, name, reason, generation, now],
        ).map_err(|_| ControllerError::Storage)?;
        self.prune_decision_events()?;
        Ok(ControllerReceipt {
            request_id: request_id.into(),
            decision,
            reason: reason.into(),
            generation,
        })
    }
    pub fn decision_history(
        &self,
        request_id: &str,
    ) -> Result<Vec<DecisionRecord>, ControllerError> {
        let mut statement = self.connection.prepare("SELECT request_id,decision,reason,generation,recorded_at FROM decision_events WHERE request_id=?1 ORDER BY id").map_err(|_|ControllerError::Storage)?;
        let rows = statement
            .query_map([request_id], |row| {
                let decision: String = row.get(1)?;
                Ok(DecisionRecord {
                    request_id: row.get(0)?,
                    decision: match decision.as_str() {
                        "accepted" => DecisionState::Accepted,
                        "rejected" => DecisionState::Rejected,
                        "deferred" => DecisionState::Deferred,
                        "partial" => DecisionState::Partial,
                        _ => DecisionState::Failed,
                    },
                    reason: row.get(2)?,
                    generation: row.get(3)?,
                    recorded_at: row.get(4)?,
                })
            })
            .map_err(|_| ControllerError::Storage)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| ControllerError::Storage)
    }
    pub fn evaluate(
        &mut self,
        request: &ManagementRequest,
        now: u64,
    ) -> Result<ControllerReceipt, ControllerError> {
        let result = self.evaluate_authorized(request, now, None);
        if let Err(error) = &result {
            self.record_rejection(&request.request_id, &error.to_string(), now)?;
        }
        result
    }
    pub fn authorize_adapter_operation(
        &mut self,
        request: &ManagementRequest,
        operation: AdapterOperation,
        now: u64,
    ) -> Result<(ControllerReceipt, AuthorizedAdapterOperation), ControllerError> {
        if request.request_id != operation.operation_id
            || request.action != operation.action
            || request.resource_ids.len() != 1
            || request.resource_ids[0] != operation.target_id
            || request.payload_digest != operation.desired_digest
            || request.plan_digest != operation.plan_digest
            || operation.expires_at > request.expires_at
        {
            return Err(ControllerError::AdapterBinding);
        }
        let receipt = self.evaluate(request, now)?;
        Ok((
            receipt,
            AuthorizedAdapterOperation::from_controller(operation),
        ))
    }
    pub fn authorize_apply_gate(
        &mut self,
        gate: &LocalApplyGateV1,
        now: u64,
    ) -> Result<(ApplyAuthorizationReceiptV1, AuthorizedAdapterOperation), ControllerError> {
        validate_apply_gate(gate, now).map_err(|_| ControllerError::ApplyGate)?;
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&gate.authorization.signature)
                .map_err(|_| ControllerError::Signature)?,
        )
        .map_err(|_| ControllerError::Signature)?;
        self.verifying_key
            .verify(
                &authorization_signing_bytes(&gate.authorization)
                    .map_err(|_| ControllerError::ApplyGate)?,
                &signature,
            )
            .map_err(|_| ControllerError::Signature)?;
        let operation_digest = digest(&gate.operation).map_err(ControllerError::Core)?;
        let authority_context_digest =
            digest(&gate.authorization).map_err(ControllerError::Core)?;
        let receipt = self.evaluate_authorized(
            &gate.request,
            now,
            Some(ApplyAuthorizationBinding {
                operation_digest: operation_digest.clone(),
                authority_context_digest: authority_context_digest.clone(),
            }),
        )?;
        let operation = AuthorizedAdapterOperation::from_controller(gate.operation.clone());
        Ok((
            ApplyAuthorizationReceiptV1::from_controller(
                receipt,
                operation_digest,
                authority_context_digest,
            ),
            operation,
        ))
    }
    pub fn resume_authorized_apply(
        &self,
        gate: &LocalApplyGateV1,
        now: u64,
    ) -> Result<(ApplyAuthorizationReceiptV1, AuthorizedAdapterOperation), ControllerError> {
        validate_apply_gate(gate, now).map_err(|_| ControllerError::ApplyGate)?;
        self.verify_request_signature(&gate.request)?;
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&gate.authorization.signature)
                .map_err(|_| ControllerError::Signature)?,
        )
        .map_err(|_| ControllerError::Signature)?;
        self.verifying_key
            .verify(
                &authorization_signing_bytes(&gate.authorization)
                    .map_err(|_| ControllerError::ApplyGate)?,
                &signature,
            )
            .map_err(|_| ControllerError::Signature)?;
        let expected_operation = digest(&gate.operation).map_err(ControllerError::Core)?;
        let expected_context = digest(&gate.authorization).map_err(ControllerError::Core)?;
        let stored = self.connection.query_row(
            "SELECT operation_digest,authority_context_digest,accepted_generation FROM apply_authorizations WHERE request_id=?1",
            [&gate.request.request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?)),
        ).optional().map_err(|_| ControllerError::Storage)?
            .ok_or(ControllerError::ApplyGate)?;
        if stored.0 != expected_operation || stored.1 != expected_context {
            return Err(ControllerError::ApplyGate);
        }
        let receipt = ControllerReceipt {
            request_id: gate.request.request_id.clone(),
            decision: DecisionState::Accepted,
            reason: "AUTHORIZED".into(),
            generation: stored.2,
        };
        Ok((
            ApplyAuthorizationReceiptV1::from_controller(receipt, stored.0, stored.1),
            AuthorizedAdapterOperation::from_controller(gate.operation.clone()),
        ))
    }
    pub fn authorize_recovery_gate(
        &mut self,
        gate: &LocalRecoveryGateV1,
        now: u64,
    ) -> Result<(ApplyAuthorizationReceiptV1, AuthorizedAdapterOperation), ControllerError> {
        validate_recovery_gate(gate, now).map_err(|_| ControllerError::ApplyGate)?;
        self.verify_authorization_signature(&gate.authorization)?;
        let operation_digest = digest(&gate.operation).map_err(ControllerError::Core)?;
        let authority_context_digest =
            digest(&gate.authorization).map_err(ControllerError::Core)?;
        let receipt = self.evaluate_authorized(
            &gate.request,
            now,
            Some(ApplyAuthorizationBinding {
                operation_digest: operation_digest.clone(),
                authority_context_digest: authority_context_digest.clone(),
            }),
        )?;
        Ok((
            ApplyAuthorizationReceiptV1::from_controller(
                receipt,
                operation_digest,
                authority_context_digest,
            ),
            AuthorizedAdapterOperation::from_controller(gate.operation.clone()),
        ))
    }
    pub fn resume_authorized_recovery(
        &self,
        gate: &LocalRecoveryGateV1,
        now: u64,
    ) -> Result<(ApplyAuthorizationReceiptV1, AuthorizedAdapterOperation), ControllerError> {
        validate_recovery_gate(gate, now).map_err(|_| ControllerError::ApplyGate)?;
        self.verify_request_signature(&gate.request)?;
        self.verify_authorization_signature(&gate.authorization)?;
        self.resume_bound_operation(
            &gate.request.request_id,
            &gate.operation,
            &gate.authorization,
        )
    }
    pub fn accept_plan_submission(
        &mut self,
        submission: &LocalPlanSubmissionV1,
        now: u64,
    ) -> Result<PlanSubmissionReceiptV1, ControllerError> {
        validate_plan_submission(submission)?;
        self.evaluate(&submission.request, now)
            .map(PlanSubmissionReceiptV1::from_controller)
    }
    fn verify_request_signature(&self, request: &ManagementRequest) -> Result<(), ControllerError> {
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&request.signature)
                .map_err(|_| ControllerError::Signature)?,
        )
        .map_err(|_| ControllerError::Signature)?;
        self.verifying_key
            .verify(&Self::signing_bytes(request)?, &signature)
            .map_err(|_| ControllerError::Signature)
    }
    fn verify_authorization_signature(
        &self,
        authorization: &crate::apply_gate::ApplyAuthorizationEvidenceV1,
    ) -> Result<(), ControllerError> {
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&authorization.signature)
                .map_err(|_| ControllerError::Signature)?,
        )
        .map_err(|_| ControllerError::Signature)?;
        self.verifying_key
            .verify(
                &authorization_signing_bytes(authorization)
                    .map_err(|_| ControllerError::ApplyGate)?,
                &signature,
            )
            .map_err(|_| ControllerError::Signature)
    }
    fn resume_bound_operation(
        &self,
        request_id: &str,
        operation: &AdapterOperation,
        authorization: &crate::apply_gate::ApplyAuthorizationEvidenceV1,
    ) -> Result<(ApplyAuthorizationReceiptV1, AuthorizedAdapterOperation), ControllerError> {
        let expected_operation = digest(operation).map_err(ControllerError::Core)?;
        let expected_context = digest(authorization).map_err(ControllerError::Core)?;
        let stored = self.connection.query_row(
            "SELECT operation_digest,authority_context_digest,accepted_generation FROM apply_authorizations WHERE request_id=?1",
            [request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?)),
        ).optional().map_err(|_| ControllerError::Storage)?.ok_or(ControllerError::ApplyGate)?;
        if stored.0 != expected_operation || stored.1 != expected_context {
            return Err(ControllerError::ApplyGate);
        }
        let receipt = ControllerReceipt {
            request_id: request_id.into(),
            decision: DecisionState::Accepted,
            reason: "AUTHORIZED".into(),
            generation: stored.2,
        };
        Ok((
            ApplyAuthorizationReceiptV1::from_controller(receipt, stored.0, stored.1),
            AuthorizedAdapterOperation::from_controller(operation.clone()),
        ))
    }
    fn evaluate_authorized(
        &mut self,
        request: &ManagementRequest,
        now: u64,
        apply_binding: Option<ApplyAuthorizationBinding>,
    ) -> Result<ControllerReceipt, ControllerError> {
        if request.schema_version != "1" || request.signature_profile != SIGNATURE_PROFILE {
            return Err(ControllerError::Invalid("profile"));
        }
        for value in [
            &request.request_id,
            &request.issuer_id,
            &request.audience,
            &request.administrative_domain,
            &request.action,
            &request.nonce,
        ] {
            Self::validate_text(value, 128)?;
        }
        if request.resource_ids.is_empty() || request.resource_ids.len() > 128 {
            return Err(ControllerError::Invalid("resources"));
        }
        for resource in &request.resource_ids {
            Self::validate_text(resource, 256)?;
        }
        Self::validate_text(&request.payload_digest, 256)?;
        Self::validate_text(&request.plan_digest, 256)?;
        if request.audience != self.policy.audience
            || request.administrative_domain != self.policy.domain
        {
            return Err(ControllerError::Policy);
        }
        if now < request.issued_at
            || now > request.expires_at
            || request.expires_at - request.issued_at > 300
        {
            return Err(ControllerError::Invalid("time"));
        }
        if !self.policy.allowed_actions.contains(&request.action) {
            return Err(ControllerError::Policy);
        }
        if self.policy.high_impact_actions.contains(&request.action)
            && now.saturating_sub(self.policy.revocation_checkpoint)
                > self.policy.max_checkpoint_age
        {
            return Err(ControllerError::Policy);
        }
        self.verify_request_signature(request)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ControllerError::Storage)?;
        if tx
            .query_row(
                "SELECT request_id FROM nonces WHERE nonce=?1",
                [&request.nonce],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ControllerError::Storage)?
            .is_some()
        {
            return Err(ControllerError::Replay);
        }
        let generation: u64 = tx
            .query_row("SELECT generation FROM state WHERE id=1", [], |r| r.get(0))
            .map_err(|_| ControllerError::Storage)?;
        if request.expected_generation != generation {
            return Err(ControllerError::Generation);
        }
        let next = generation + 1;
        tx.execute(
            "INSERT INTO nonces VALUES(?1,?2,?3)",
            params![request.nonce, request.request_id, now],
        )
        .map_err(|_| ControllerError::Storage)?;
        tx.execute("UPDATE state SET generation=?1 WHERE id=1", [next])
            .map_err(|_| ControllerError::Storage)?;
        tx.execute(
            "INSERT INTO decisions VALUES(?1,'accepted','AUTHORIZED',?2)",
            params![request.request_id, next],
        )
        .map_err(|_| ControllerError::Storage)?;
        tx.execute(
            "INSERT INTO decision_events(request_id,decision,reason,generation,recorded_at) VALUES(?1,'accepted','AUTHORIZED',?2,?3)",
            params![request.request_id, next, now],
        )
        .map_err(|_| ControllerError::Storage)?;
        if let Some(binding) = apply_binding {
            tx.execute(
                "INSERT INTO apply_authorizations(request_id,operation_digest,authority_context_digest,accepted_generation) VALUES(?1,?2,?3,?4)",
                params![request.request_id, binding.operation_digest, binding.authority_context_digest, next],
            ).map_err(|_| ControllerError::Storage)?;
        }
        tx.commit().map_err(|_| ControllerError::Storage)?;
        self.prune_decision_events()?;
        Ok(ControllerReceipt {
            request_id: request.request_id.clone(),
            decision: DecisionState::Accepted,
            reason: "AUTHORIZED".into(),
            generation: next,
        })
    }
    pub fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub fn validate_plan_submission(submission: &LocalPlanSubmissionV1) -> Result<(), ControllerError> {
    if submission.schema_version != PLAN_SUBMISSION_SCHEMA
        || submission.request.action != PLAN_ACCEPT_ACTION
        || submission.plan.schema_version != "1"
        || submission.plan.operations.is_empty()
        || submission.plan.target_generation
            != submission.plan.expected_generation.saturating_add(1)
        || submission.request.expected_generation != submission.plan.expected_generation
        || submission.request.plan_digest
            != digest(&submission.plan).map_err(ControllerError::Core)?
        || submission.request.payload_digest != submission.plan.bundle_digest
    {
        return Err(ControllerError::Invalid("plan_binding"));
    }
    let resources = submission
        .plan
        .operations
        .iter()
        .map(|operation| operation.resource_id.clone())
        .collect::<BTreeSet<_>>();
    if resources.len() != submission.plan.operations.len()
        || submission.request.resource_ids != resources.into_iter().collect::<Vec<_>>()
        || submission.plan.operations.iter().any(|operation| {
            operation.expected_generation != submission.plan.expected_generation
                || operation.target_generation != submission.plan.target_generation
                || operation.action.is_empty()
                || operation.operation_id.is_empty()
                || operation.resource_id.is_empty()
        })
    {
        return Err(ControllerError::Invalid("plan_binding"));
    }
    Ok(())
}
