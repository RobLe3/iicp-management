use crate::{digest, ConvergenceState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterOperation {
    pub operation_id: String,
    pub target_id: String,
    pub action: String,
    pub plan_digest: String,
    pub desired_digest: String,
    pub expected_generation: u64,
    pub expires_at: u64,
    pub capability: String,
    pub desired: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterReceipt {
    pub operation_id: String,
    pub state: ConvergenceState,
    pub generation: u64,
    pub result_digest: String,
    pub reason: String,
}
#[derive(Debug, Error, PartialEq)]
pub enum AdapterError {
    #[error("ADAPTER_UNSUPPORTED")]
    Unsupported,
    #[error("ADAPTER_REPLAY_CONFLICT")]
    ReplayConflict,
    #[error("ADAPTER_GENERATION_CONFLICT")]
    Generation,
    #[error("ADAPTER_INVALID_CONFIG")]
    Invalid,
    #[error("ADAPTER_IO")]
    Io,
}
pub trait ManagedAdapter {
    fn capabilities(&self) -> &[String];
    fn observe(&self) -> Result<Value, AdapterError>;
    fn apply(
        &mut self,
        operation: &AdapterOperation,
        now: u64,
    ) -> Result<AdapterReceipt, AdapterError>;
    fn rollback(&mut self, operation_id: &str) -> Result<AdapterReceipt, AdapterError>;
}
pub struct SyntheticAdapter {
    pub generation: u64,
    pub state: Value,
    history: BTreeMap<String, (String, Value, AdapterReceipt)>,
}
impl SyntheticAdapter {
    pub fn new() -> Self {
        Self {
            generation: 0,
            state: Value::Null,
            history: BTreeMap::new(),
        }
    }
}
impl Default for SyntheticAdapter {
    fn default() -> Self {
        Self::new()
    }
}
impl ManagedAdapter for SyntheticAdapter {
    fn capabilities(&self) -> &[String] {
        static C: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        C.get_or_init(|| vec!["synthetic-v1".into()])
    }
    fn observe(&self) -> Result<Value, AdapterError> {
        Ok(self.state.clone())
    }
    fn apply(&mut self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        if now > o.expires_at {
            return Err(AdapterError::Invalid);
        }
        let d = digest(&o.desired).map_err(|_| AdapterError::Invalid)?;
        if d != o.desired_digest {
            return Err(AdapterError::Invalid);
        }
        if let Some((prior, _, receipt)) = self.history.get(&o.operation_id) {
            return if prior == &d {
                Ok(receipt.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if o.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let old = self.state.clone();
        self.state = o.desired.clone();
        self.generation += 1;
        let r = AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: d.clone(),
            reason: "APPLIED".into(),
        };
        self.history
            .insert(o.operation_id.clone(), (d, old, r.clone()));
        Ok(r)
    }
    fn rollback(&mut self, id: &str) -> Result<AdapterReceipt, AdapterError> {
        let (_, old, _) = self
            .history
            .get(id)
            .cloned()
            .ok_or(AdapterError::Unsupported)?;
        self.state = old;
        self.generation += 1;
        Ok(AdapterReceipt {
            operation_id: id.into(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: digest(&self.state).map_err(|_| AdapterError::Invalid)?,
            reason: "ROLLED_BACK".into(),
        })
    }
}
pub struct RuntimeConfigAdapter {
    path: PathBuf,
    generation: u64,
    history: BTreeMap<String, (String, Vec<u8>, AdapterReceipt)>,
}
impl RuntimeConfigAdapter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            generation: 0,
            history: BTreeMap::new(),
        }
    }
    fn validate(v: &Value) -> bool {
        v.get("schema_version").and_then(Value::as_str) == Some("1") && !contains_secret(v)
    }
}
fn contains_secret(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.iter().any(|(k, v)| {
            matches!(k.as_str(), "secret" | "password" | "token" | "private_key")
                || contains_secret(v)
        }),
        Value::Array(a) => a.iter().any(contains_secret),
        _ => false,
    }
}
impl ManagedAdapter for RuntimeConfigAdapter {
    fn capabilities(&self) -> &[String] {
        static C: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        C.get_or_init(|| vec!["runtime-config-v1".into()])
    }
    fn observe(&self) -> Result<Value, AdapterError> {
        serde_json::from_slice(&fs::read(&self.path).map_err(|_| AdapterError::Io)?)
            .map_err(|_| AdapterError::Invalid)
    }
    fn apply(&mut self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        if now > o.expires_at || !Self::validate(&o.desired) {
            return Err(AdapterError::Invalid);
        }
        let d = digest(&o.desired).map_err(|_| AdapterError::Invalid)?;
        if d != o.desired_digest {
            return Err(AdapterError::Invalid);
        }
        if let Some((prior, _, r)) = self.history.get(&o.operation_id) {
            return if prior == &d {
                Ok(r.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if o.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let old = fs::read(&self.path).unwrap_or_default();
        let parent = self.path.parent().ok_or(AdapterError::Io)?;
        let mut tmp = tempfile_in(parent).map_err(|_| AdapterError::Io)?;
        serde_json::to_writer(&mut tmp.0, &o.desired).map_err(|_| AdapterError::Io)?;
        tmp.0.flush().map_err(|_| AdapterError::Io)?;
        fs::rename(&tmp.1, &self.path).map_err(|_| AdapterError::Io)?;
        if self.observe() != Ok(o.desired.clone()) {
            let _ = fs::write(&self.path, &old);
            return Err(AdapterError::Io);
        }
        self.generation += 1;
        let r = AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: d.clone(),
            reason: "APPLIED".into(),
        };
        self.history
            .insert(o.operation_id.clone(), (d, old, r.clone()));
        Ok(r)
    }
    fn rollback(&mut self, id: &str) -> Result<AdapterReceipt, AdapterError> {
        let (_, old, _) = self
            .history
            .get(id)
            .cloned()
            .ok_or(AdapterError::Unsupported)?;
        fs::write(&self.path, old).map_err(|_| AdapterError::Io)?;
        self.generation += 1;
        Ok(AdapterReceipt {
            operation_id: id.into(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: digest(&self.observe()?).map_err(|_| AdapterError::Invalid)?,
            reason: "ROLLED_BACK".into(),
        })
    }
}
fn tempfile_in(parent: &Path) -> std::io::Result<(fs::File, PathBuf)> {
    let p = parent.join(format!(".iicp-stage-{}", std::process::id()));
    let f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    }
    Ok((f, p))
}
