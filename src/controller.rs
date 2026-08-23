use crate::ManagementError;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension};
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

#[derive(Debug, Clone)]
pub struct ControllerPolicy {
    pub audience: String,
    pub domain: String,
    pub allowed_actions: BTreeSet<String>,
    pub revocation_checkpoint: u64,
    pub max_checkpoint_age: u64,
    pub high_impact_actions: BTreeSet<String>,
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
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL); INSERT OR IGNORE INTO state VALUES(1,0); CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, request_id TEXT NOT NULL, consumed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS decisions(request_id TEXT PRIMARY KEY, decision TEXT NOT NULL, reason TEXT NOT NULL, generation INTEGER NOT NULL);").map_err(|_|ControllerError::Storage)?;
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
    pub fn evaluate(
        &mut self,
        request: &ManagementRequest,
        now: u64,
    ) -> Result<ControllerReceipt, ControllerError> {
        if request.schema_version != "1" || request.signature_profile != SIGNATURE_PROFILE {
            return Err(ControllerError::Invalid("profile"));
        }
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
            .transaction()
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
        tx.commit().map_err(|_| ControllerError::Storage)?;
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
