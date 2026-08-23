use crate::ManagementError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionRecord {
    pub request_id: String,
    pub decision: DecisionState,
    pub reason: String,
    pub generation: u64,
    pub recorded_at: u64,
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
    #[error(transparent)]
    Core(#[from] ManagementError),
}

pub struct Controller {
    connection: Connection,
    policy: ControllerPolicy,
    verifying_key: VerifyingKey,
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
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL); INSERT OR IGNORE INTO state VALUES(1,0); CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL, consumed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS decisions(request_id TEXT PRIMARY KEY, decision TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS decision_events(id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL, recorded_at INTEGER NOT NULL);").map_err(|_|ControllerError::Storage)?;
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
        let result = self.evaluate_authorized(request, now);
        if let Err(error) = &result {
            self.record_rejection(&request.request_id, &error.to_string(), now)?;
        }
        result
    }
    fn evaluate_authorized(
        &mut self,
        request: &ManagementRequest,
        now: u64,
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
        let signature = Signature::from_slice(
            &STANDARD
                .decode(&request.signature)
                .map_err(|_| ControllerError::Signature)?,
        )
        .map_err(|_| ControllerError::Signature)?;
        self.verifying_key
            .verify(&Self::signing_bytes(request)?, &signature)
            .map_err(|_| ControllerError::Signature)?;
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
