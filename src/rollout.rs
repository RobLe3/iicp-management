use crate::apply_gate::{validate_apply_gate, LocalApplyGateV1};
use crate::controller::{DecisionState, SIGNATURE_PROFILE};
use crate::digest;
use crate::execution::{ApplyLifecycleReceiptV1, ExecutionState};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

pub const ROLLOUT_SCHEMA: &str = "iicp.management-rollout.v1";
pub const PARTIAL_ACCEPTANCE_SCHEMA: &str = "iicp.management-partial-acceptance.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    StopAndHold,
    ContinueIndependent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutTargetV1 {
    pub target_id: String,
    pub executor_ref: String,
    pub batch: u32,
    pub required: bool,
    pub gate: LocalApplyGateV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRunV1 {
    pub schema_version: String,
    pub run_id: String,
    pub administrative_domain: String,
    pub audience: String,
    pub failure_policy: FailurePolicy,
    pub created_at: u64,
    pub expires_at: u64,
    pub targets: Vec<RolloutTargetV1>,
    pub authorizes_target_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Pending,
    Running,
    Paused,
    Converged,
    PartiallyConverged,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetRunState {
    Pending,
    Running,
    Converged,
    Deferred,
    Rejected,
    Failed,
    Held,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TargetRunStatusV1 {
    pub target_id: String,
    pub executor_ref: String,
    pub batch: u32,
    pub required: bool,
    pub state: TargetRunState,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ApplyLifecycleReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConvergenceStatusV1 {
    pub schema_version: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub version: u64,
    pub state: RunState,
    pub current_batch: u32,
    pub partial_accepted: bool,
    pub authorizes_target_execution: bool,
    pub targets: Vec<TargetRunStatusV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialAcceptanceV1 {
    pub schema_version: String,
    pub acceptance_id: String,
    pub issuer_id: String,
    pub audience: String,
    pub administrative_domain: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub expected_run_version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature_profile: String,
    pub signature: String,
}

pub fn validate_manifest(value: &OperationRunV1, now: u64) -> Result<String, String> {
    if value.schema_version != ROLLOUT_SCHEMA
        || value.authorizes_target_execution
        || value.run_id.trim().is_empty()
        || value.administrative_domain.trim().is_empty()
        || value.audience.trim().is_empty()
        || value.created_at > now
        || value.created_at >= value.expires_at
        || now > value.expires_at
        || value.targets.is_empty()
        || value.targets.len() > 10_000
    {
        return Err("ROLLOUT_MANIFEST_INVALID".into());
    }
    let mut target_ids = BTreeSet::new();
    let mut operation_ids = BTreeSet::new();
    let mut batches = BTreeSet::new();
    for target in &value.targets {
        if target.target_id.trim().is_empty()
            || target.executor_ref.trim().is_empty()
            || !target_ids.insert(target.target_id.as_str())
            || !operation_ids.insert(target.gate.operation.operation_id.as_str())
            || target.target_id != target.gate.operation.target_id
            || target.gate.authorization.administrative_domain != value.administrative_domain
            || target.gate.request.administrative_domain != value.administrative_domain
            || target.gate.authorization.audience != value.audience
            || target.gate.request.audience != value.audience
            || target.gate.request.expires_at > value.expires_at
        {
            return Err("ROLLOUT_TARGET_BINDING_INVALID".into());
        }
        validate_apply_gate(&target.gate, now).map_err(|_| "ROLLOUT_TARGET_GATE_INVALID")?;
        batches.insert(target.batch);
    }
    let canary = value.targets.iter().filter(|target| target.batch == 0);
    if canary.clone().count() != 1 || !canary.into_iter().all(|target| target.required) {
        return Err("ROLLOUT_CANARY_INVALID".into());
    }
    if batches
        .iter()
        .copied()
        .enumerate()
        .any(|(expected, actual)| expected as u32 != actual)
    {
        return Err("ROLLOUT_BATCH_SEQUENCE_INVALID".into());
    }
    digest(value).map_err(|error| error.to_string())
}

pub fn partial_acceptance_signing_bytes(value: &PartialAcceptanceV1) -> Result<Vec<u8>, String> {
    let mut projection = serde_json::to_value(value).map_err(|_| "PARTIAL_ACCEPTANCE_INVALID")?;
    projection
        .as_object_mut()
        .ok_or("PARTIAL_ACCEPTANCE_INVALID")?
        .remove("signature");
    serde_jcs::to_vec(&projection).map_err(|_| "PARTIAL_ACCEPTANCE_INVALID".into())
}

pub fn verify_partial_acceptance(
    value: &PartialAcceptanceV1,
    status: &ConvergenceStatusV1,
    public_key: [u8; 32],
    now: u64,
) -> Result<(), String> {
    if value.schema_version != PARTIAL_ACCEPTANCE_SCHEMA
        || value.signature_profile != SIGNATURE_PROFILE
        || value.acceptance_id.trim().is_empty()
        || value.issuer_id.trim().is_empty()
        || value.audience.trim().is_empty()
        || value.administrative_domain.trim().is_empty()
        || value.run_id != status.run_id
        || value.manifest_digest != status.manifest_digest
        || value.expected_run_version != status.version
        || value.issued_at > now
        || value.issued_at >= value.expires_at
        || now > value.expires_at
        || status.state != RunState::PartiallyConverged
        || status.partial_accepted
    {
        return Err("PARTIAL_ACCEPTANCE_INVALID".into());
    }
    let key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| "PARTIAL_ACCEPTANCE_KEY_INVALID")?;
    let signature = Signature::from_slice(
        &STANDARD
            .decode(&value.signature)
            .map_err(|_| "PARTIAL_ACCEPTANCE_SIGNATURE_INVALID")?,
    )
    .map_err(|_| "PARTIAL_ACCEPTANCE_SIGNATURE_INVALID")?;
    key.verify(&partial_acceptance_signing_bytes(value)?, &signature)
        .map_err(|_| "PARTIAL_ACCEPTANCE_SIGNATURE_INVALID".into())
}

pub struct RolloutStore {
    connection: Connection,
}

impl RolloutStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS runs(
               run_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL, manifest_digest TEXT NOT NULL,
               state TEXT NOT NULL, current_batch INTEGER NOT NULL, version INTEGER NOT NULL,
               partial_accepted INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rollout_targets(
               run_id TEXT NOT NULL, target_id TEXT NOT NULL, executor_ref TEXT NOT NULL,
               batch INTEGER NOT NULL, required INTEGER NOT NULL, state TEXT NOT NULL,
               reason TEXT NOT NULL, receipt_json TEXT,
               PRIMARY KEY(run_id,target_id)
             );",
        ).map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        Ok(Self { connection })
    }

    pub fn create(
        &mut self,
        manifest: &OperationRunV1,
        now: u64,
    ) -> Result<ConvergenceStatusV1, String> {
        let manifest_digest = validate_manifest(manifest, now)?;
        let manifest_json =
            serde_json::to_string(manifest).map_err(|_| "ROLLOUT_SERIALIZATION_FAILED")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO runs(run_id,manifest_json,manifest_digest,state,current_batch,version,partial_accepted,created_at,updated_at) VALUES(?1,?2,?3,'pending',0,0,0,?4,?4)",
            params![manifest.run_id, manifest_json, manifest_digest, now],
        ).map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        if inserted == 0 {
            let existing: String = transaction
                .query_row(
                    "SELECT manifest_digest FROM runs WHERE run_id=?1",
                    [&manifest.run_id],
                    |row| row.get(0),
                )
                .map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
            if existing != manifest_digest {
                return Err("ROLLOUT_RUN_ID_COLLISION".into());
            }
        } else {
            for target in &manifest.targets {
                transaction.execute(
                    "INSERT INTO rollout_targets(run_id,target_id,executor_ref,batch,required,state,reason) VALUES(?1,?2,?3,?4,?5,'pending','ROLLOUT_PENDING')",
                    params![manifest.run_id,target.target_id,target.executor_ref,target.batch,u8::from(target.required)],
                ).map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
            }
        }
        transaction.commit().map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        self.status(&manifest.run_id)
    }

    pub fn status(&self, run_id: &str) -> Result<ConvergenceStatusV1, String> {
        let row = self.connection.query_row(
            "SELECT manifest_json,manifest_digest,state,current_batch,version,partial_accepted FROM runs WHERE run_id=?1",
            [run_id],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,u32>(3)?,row.get::<_,u64>(4)?,row.get::<_,bool>(5)?)),
        ).optional().map_err(|_| "ROLLOUT_STORAGE_FAILED")?.ok_or("ROLLOUT_NOT_FOUND")?;
        let _: OperationRunV1 =
            serde_json::from_str(&row.0).map_err(|_| "ROLLOUT_STORAGE_CORRUPT")?;
        let mut statement = self.connection.prepare(
            "SELECT target_id,executor_ref,batch,required,state,reason,receipt_json FROM rollout_targets WHERE run_id=?1 ORDER BY batch,target_id"
        ).map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        let targets = statement
            .query_map([run_id], |target| {
                let receipt_json: Option<String> = target.get(6)?;
                Ok((
                    target.get::<_, String>(0)?,
                    target.get::<_, String>(1)?,
                    target.get::<_, u32>(2)?,
                    target.get::<_, bool>(3)?,
                    target.get::<_, String>(4)?,
                    target.get::<_, String>(5)?,
                    receipt_json,
                ))
            })
            .map_err(|_| "ROLLOUT_STORAGE_FAILED")?
            .map(|item| {
                let item = item.map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
                Ok(TargetRunStatusV1 {
                    target_id: item.0,
                    executor_ref: item.1,
                    batch: item.2,
                    required: item.3,
                    state: parse_target_state(&item.4)?,
                    reason: item.5,
                    receipt: item
                        .6
                        .map(|json| {
                            serde_json::from_str(&json).map_err(|_| "ROLLOUT_STORAGE_CORRUPT")
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ConvergenceStatusV1 {
            schema_version: ROLLOUT_SCHEMA.into(),
            run_id: run_id.into(),
            manifest_digest: row.1,
            version: row.4,
            state: parse_run_state(&row.2)?,
            current_batch: row.3,
            partial_accepted: row.5,
            authorizes_target_execution: false,
            targets,
        })
    }

    pub fn manifest(&self, run_id: &str) -> Result<OperationRunV1, String> {
        let json: String = self
            .connection
            .query_row(
                "SELECT manifest_json FROM runs WHERE run_id=?1",
                [run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| "ROLLOUT_STORAGE_FAILED")?
            .ok_or("ROLLOUT_NOT_FOUND")?;
        serde_json::from_str(&json).map_err(|_| "ROLLOUT_STORAGE_CORRUPT".into())
    }

    pub fn pause(&mut self, run_id: &str, now: u64) -> Result<ConvergenceStatusV1, String> {
        self.transition_run(run_id, "paused", "running", now)?;
        self.status(run_id)
    }

    pub fn resume(&mut self, run_id: &str, now: u64) -> Result<ConvergenceStatusV1, String> {
        self.transition_run(run_id, "running", "paused", now)?;
        self.status(run_id)
    }

    fn transition_run(
        &mut self,
        run_id: &str,
        to: &str,
        from: &str,
        now: u64,
    ) -> Result<(), String> {
        let changed=self.connection.execute("UPDATE runs SET state=?2,version=version+1,updated_at=?3 WHERE run_id=?1 AND state=?4",params![run_id,to,now,from]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        if changed != 1 {
            return Err("ROLLOUT_STATE_TRANSITION_INVALID".into());
        }
        Ok(())
    }

    pub fn runnable_targets(&self, run_id: &str) -> Result<Vec<RolloutTargetV1>, String> {
        let status = self.status(run_id)?;
        if matches!(
            status.state,
            RunState::Paused | RunState::Converged | RunState::Failed
        ) {
            return Err("ROLLOUT_NOT_RUNNABLE".into());
        }
        let manifest = self.manifest(run_id)?;
        Ok(manifest
            .targets
            .into_iter()
            .filter(|target| {
                target.batch == status.current_batch
                    && status
                        .targets
                        .iter()
                        .find(|item| item.target_id == target.target_id)
                        .is_some_and(|item| {
                            matches!(
                                item.state,
                                TargetRunState::Pending | TargetRunState::Running
                            )
                        })
            })
            .collect())
    }

    pub fn mark_running(&mut self, run_id: &str, target_id: &str, now: u64) -> Result<(), String> {
        let changed = self.connection.execute("UPDATE rollout_targets SET state='running',reason='ROLLOUT_EXECUTION_STARTED' WHERE run_id=?1 AND target_id=?2 AND state IN ('pending','running')",params![run_id,target_id]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        if changed != 1 {
            return Err("ROLLOUT_TARGET_NOT_RUNNABLE".into());
        }
        self.connection.execute("UPDATE runs SET state='running',updated_at=?2 WHERE run_id=?1 AND state IN ('pending','running')",params![run_id,now]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        run_id: &str,
        target_id: &str,
        receipt: &ApplyLifecycleReceiptV1,
        now: u64,
    ) -> Result<ConvergenceStatusV1, String> {
        let manifest = self.manifest(run_id)?;
        let target = manifest
            .targets
            .iter()
            .find(|target| target.target_id == target_id)
            .ok_or("ROLLOUT_TARGET_NOT_FOUND")?;
        if receipt.operation_id != target.gate.operation.operation_id {
            return Err("ROLLOUT_RECEIPT_BINDING_INVALID".into());
        }
        let (state, reason) = match receipt.state {
            ExecutionState::Converged => ("converged", receipt.reason.as_str()),
            ExecutionState::PartiallyConverged => ("failed", receipt.reason.as_str()),
            ExecutionState::Deferred => ("deferred", receipt.reason.as_str()),
            ExecutionState::Failed
                if receipt.controller_authorization.decision == DecisionState::Rejected =>
            {
                ("rejected", receipt.reason.as_str())
            }
            ExecutionState::Failed => ("failed", receipt.reason.as_str()),
        };
        let json = serde_json::to_string(receipt).map_err(|_| "ROLLOUT_SERIALIZATION_FAILED")?;
        let changed = self.connection.execute("UPDATE rollout_targets SET state=?3,reason=?4,receipt_json=?5 WHERE run_id=?1 AND target_id=?2 AND state IN ('pending','running','deferred','held')",params![run_id,target_id,state,reason,json]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        if changed != 1 {
            return Err("ROLLOUT_TARGET_NOT_RUNNABLE".into());
        }
        self.recalculate(run_id, now)?;
        self.status(run_id)
    }

    pub fn record_execution_error(
        &mut self,
        run_id: &str,
        target_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<ConvergenceStatusV1, String> {
        self.connection.execute("UPDATE rollout_targets SET state='deferred',reason=?3 WHERE run_id=?1 AND target_id=?2 AND state IN ('pending','running','deferred')",params![run_id,target_id,reason]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        self.recalculate(run_id, now)?;
        self.status(run_id)
    }

    fn recalculate(&mut self, run_id: &str, now: u64) -> Result<(), String> {
        let manifest = self.manifest(run_id)?;
        let status = self.status(run_id)?;
        let batch_targets = status
            .targets
            .iter()
            .filter(|target| target.batch == status.current_batch)
            .collect::<Vec<_>>();
        if batch_targets.iter().any(|target| {
            matches!(
                target.state,
                TargetRunState::Pending | TargetRunState::Running
            )
        }) {
            return Ok(());
        }
        let required_failure = batch_targets
            .iter()
            .any(|target| target.required && target.state != TargetRunState::Converged);
        let optional_failure = batch_targets
            .iter()
            .any(|target| !target.required && target.state != TargetRunState::Converged);
        let last_batch = manifest
            .targets
            .iter()
            .map(|target| target.batch)
            .max()
            .unwrap_or(0);
        let final_incomplete = status.current_batch > 0
            && status.current_batch == last_batch
            && (required_failure || optional_failure);
        let (state, next_batch) = if final_incomplete {
            ("partially_converged", status.current_batch)
        } else if required_failure
            || (optional_failure && manifest.failure_policy == FailurePolicy::StopAndHold)
        {
            ("paused", status.current_batch)
        } else if status.current_batch < last_batch {
            ("running", status.current_batch + 1)
        } else {
            let all = status
                .targets
                .iter()
                .all(|target| target.state == TargetRunState::Converged);
            if all {
                ("converged", status.current_batch)
            } else {
                ("partially_converged", status.current_batch)
            }
        };
        self.connection.execute("UPDATE runs SET state=?2,current_batch=?3,version=version+1,updated_at=?4 WHERE run_id=?1",params![run_id,state,next_batch,now]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        Ok(())
    }

    pub fn prepare_retry(
        &mut self,
        run_id: &str,
        target_id: &str,
        now: u64,
    ) -> Result<RolloutTargetV1, String> {
        let status = self.status(run_id)?;
        let target_status = status
            .targets
            .iter()
            .find(|target| target.target_id == target_id)
            .ok_or("ROLLOUT_TARGET_NOT_FOUND")?;
        if target_status.state != TargetRunState::Deferred {
            return Err("ROLLOUT_RETRY_NOT_ALLOWED".into());
        }
        self.connection.execute("UPDATE rollout_targets SET state='running',reason='ROLLOUT_EXPLICIT_RETRY' WHERE run_id=?1 AND target_id=?2",params![run_id,target_id]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        self.connection
            .execute(
                "UPDATE runs SET state='running',version=version+1,updated_at=?2 WHERE run_id=?1",
                params![run_id, now],
            )
            .map_err(|_| "ROLLOUT_STORAGE_FAILED")?;
        self.manifest(run_id)?
            .targets
            .into_iter()
            .find(|target| target.target_id == target_id)
            .ok_or("ROLLOUT_TARGET_NOT_FOUND".into())
    }

    pub fn accept_partial(
        &mut self,
        value: &PartialAcceptanceV1,
        public_key: [u8; 32],
        now: u64,
    ) -> Result<ConvergenceStatusV1, String> {
        let status = self.status(&value.run_id)?;
        let manifest = self.manifest(&value.run_id)?;
        if value.administrative_domain != manifest.administrative_domain {
            return Err("PARTIAL_ACCEPTANCE_INVALID".into());
        }
        if value.audience != manifest.audience {
            return Err("PARTIAL_ACCEPTANCE_INVALID".into());
        }
        verify_partial_acceptance(value, &status, public_key, now)?;
        let changed=self.connection.execute("UPDATE runs SET partial_accepted=1,version=version+1,updated_at=?2 WHERE run_id=?1 AND version=?3 AND state='partially_converged' AND partial_accepted=0",params![value.run_id,now,value.expected_run_version]).map_err(|_|"ROLLOUT_STORAGE_FAILED")?;
        if changed != 1 {
            return Err("PARTIAL_ACCEPTANCE_STALE".into());
        }
        self.status(&value.run_id)
    }
}

fn parse_run_state(value: &str) -> Result<RunState, String> {
    match value {
        "pending" => Ok(RunState::Pending),
        "running" => Ok(RunState::Running),
        "paused" => Ok(RunState::Paused),
        "converged" => Ok(RunState::Converged),
        "partially_converged" => Ok(RunState::PartiallyConverged),
        "failed" => Ok(RunState::Failed),
        _ => Err("ROLLOUT_STORAGE_CORRUPT".into()),
    }
}
fn parse_target_state(value: &str) -> Result<TargetRunState, String> {
    match value {
        "pending" => Ok(TargetRunState::Pending),
        "running" => Ok(TargetRunState::Running),
        "converged" => Ok(TargetRunState::Converged),
        "deferred" => Ok(TargetRunState::Deferred),
        "rejected" => Ok(TargetRunState::Rejected),
        "failed" => Ok(TargetRunState::Failed),
        "held" => Ok(TargetRunState::Held),
        _ => Err("ROLLOUT_STORAGE_CORRUPT".into()),
    }
}
