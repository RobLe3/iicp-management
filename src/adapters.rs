use crate::{digest, ConvergenceState};
use iicp_client::runtime_config::RuntimeConfigV1;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_operation_id: Option<String>,
}
#[derive(Debug, Clone)]
pub struct AuthorizedAdapterOperation(AdapterOperation);

impl AuthorizedAdapterOperation {
    pub(crate) fn from_controller(operation: AdapterOperation) -> Self {
        Self(operation)
    }

    pub fn operation(&self) -> &AdapterOperation {
        &self.0
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterDescriptor {
    pub capabilities: Vec<String>,
    pub actions: Vec<String>,
    pub permissions: Vec<String>,
    pub outbound_only: bool,
    pub resolves_secret_references: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[error("ADAPTER_UNKNOWN_TARGET")]
    UnknownTarget,
    #[error("ADAPTER_CANCELLED")]
    Cancelled,
}
pub trait ManagedAdapter {
    fn descriptor(&self) -> AdapterDescriptor;
    fn observe(&self) -> Result<Value, AdapterError>;
    fn apply(
        &mut self,
        operation: &AdapterOperation,
        now: u64,
    ) -> Result<AdapterReceipt, AdapterError>;
    fn rollback(&mut self, operation: &AdapterOperation) -> Result<AdapterReceipt, AdapterError>;
    fn dry_run(
        &self,
        operation: &AdapterOperation,
        now: u64,
    ) -> Result<AdapterReceipt, AdapterError>;
    fn verify(&self, operation: &AdapterOperation) -> Result<AdapterReceipt, AdapterError>;
}
pub struct AdapterHost {
    adapters: BTreeMap<(String, String), Box<dyn ManagedAdapter>>,
    cancelled: BTreeSet<String>,
    completed: BTreeMap<String, (String, AdapterReceipt)>,
}
impl AdapterHost {
    pub fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
            cancelled: BTreeSet::new(),
            completed: BTreeMap::new(),
        }
    }
    pub fn register(
        &mut self,
        target: impl Into<String>,
        capability: impl Into<String>,
        adapter: Box<dyn ManagedAdapter>,
    ) {
        self.adapters
            .insert((target.into(), capability.into()), adapter);
    }
    pub fn cancel(&mut self, operation_id: &str) {
        self.cancelled.insert(operation_id.into());
    }
    pub fn execute(
        &mut self,
        authorized: &AuthorizedAdapterOperation,
        now: u64,
    ) -> Result<AdapterReceipt, AdapterError> {
        let operation = authorized.operation();
        validate_operation(operation, now)?;
        let binding = operation_binding(operation)?;
        if let Some((prior, receipt)) = self.completed.get(&operation.operation_id) {
            return if prior == &binding {
                Ok(receipt.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if self.cancelled.contains(&operation.operation_id) {
            return Err(AdapterError::Cancelled);
        }
        let adapter = self
            .adapters
            .get_mut(&(operation.target_id.clone(), operation.capability.clone()))
            .ok_or(AdapterError::UnknownTarget)?;
        if !adapter
            .descriptor()
            .capabilities
            .iter()
            .any(|value| value == &operation.capability)
        {
            return Err(AdapterError::Unsupported);
        }
        let receipt = match operation.action.as_str() {
            "dry_run" => adapter.dry_run(operation, now),
            "apply" => adapter.apply(operation, now),
            "verify" | "observe" => adapter.verify(operation),
            "rollback" => adapter.rollback(operation),
            _ => Err(AdapterError::Unsupported),
        }?;
        self.completed
            .insert(operation.operation_id.clone(), (binding, receipt.clone()));
        Ok(receipt)
    }
}
impl Default for AdapterHost {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_operation(operation: &AdapterOperation, now: u64) -> Result<(), AdapterError> {
    if now > operation.expires_at
        || operation.operation_id.is_empty()
        || operation.operation_id.len() > 128
        || operation.target_id.is_empty()
        || operation.target_id.len() > 256
        || operation.plan_digest.is_empty()
        || operation.plan_digest.len() > 256
        || operation.desired_digest.is_empty()
        || operation.desired_digest.len() > 256
        || operation
            .related_operation_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 128)
    {
        return Err(AdapterError::Invalid);
    }
    Ok(())
}

fn operation_binding(operation: &AdapterOperation) -> Result<String, AdapterError> {
    digest(operation).map_err(|_| AdapterError::Invalid)
}
pub struct SyntheticAdapter {
    pub generation: u64,
    pub state: Value,
    history: BTreeMap<String, (String, Value, AdapterReceipt)>,
    rollback_history: BTreeMap<String, (String, AdapterReceipt)>,
}
impl SyntheticAdapter {
    pub fn new() -> Self {
        Self {
            generation: 0,
            state: Value::Null,
            history: BTreeMap::new(),
            rollback_history: BTreeMap::new(),
        }
    }
}
impl Default for SyntheticAdapter {
    fn default() -> Self {
        Self::new()
    }
}
impl ManagedAdapter for SyntheticAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            capabilities: vec!["synthetic-v1".into()],
            actions: vec![
                "observe".into(),
                "dry_run".into(),
                "apply".into(),
                "verify".into(),
                "rollback".into(),
            ],
            permissions: vec!["memory:synthetic-state".into()],
            outbound_only: true,
            resolves_secret_references: false,
        }
    }
    fn observe(&self) -> Result<Value, AdapterError> {
        Ok(self.state.clone())
    }
    fn apply(&mut self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        validate_operation(o, now)?;
        let d = digest(&o.desired).map_err(|_| AdapterError::Invalid)?;
        if d != o.desired_digest {
            return Err(AdapterError::Invalid);
        }
        let binding = operation_binding(o)?;
        if let Some((prior, _, receipt)) = self.history.get(&o.operation_id) {
            return if prior == &binding {
                Ok(receipt.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if o.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let old = self.state.clone();
        let simulation = o.desired.get("simulate").and_then(Value::as_str);
        let (state, reason) = match simulation {
            Some("partial") => {
                self.state = serde_json::json!({"partial": true});
                self.generation += 1;
                (ConvergenceState::PartiallyConverged, "SYNTHETIC_PARTIAL")
            }
            Some("irrecoverable_failure") => {
                (ConvergenceState::Failed, "SYNTHETIC_IRRECOVERABLE_FAILURE")
            }
            _ => {
                self.state = o.desired.clone();
                self.generation += 1;
                (ConvergenceState::Converged, "APPLIED")
            }
        };
        let r = AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state,
            generation: self.generation,
            result_digest: digest(&self.state).map_err(|_| AdapterError::Invalid)?,
            reason: reason.into(),
        };
        self.history
            .insert(o.operation_id.clone(), (binding, old, r.clone()));
        Ok(r)
    }
    fn rollback(&mut self, operation: &AdapterOperation) -> Result<AdapterReceipt, AdapterError> {
        let binding = operation_binding(operation)?;
        if let Some((prior, receipt)) = self.rollback_history.get(&operation.operation_id) {
            return if prior == &binding {
                Ok(receipt.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if operation.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let id = operation
            .related_operation_id
            .as_deref()
            .ok_or(AdapterError::Invalid)?;
        let (_, old, _) = self
            .history
            .get(id)
            .cloned()
            .ok_or(AdapterError::Unsupported)?;
        self.state = old;
        self.generation += 1;
        let receipt = AdapterReceipt {
            operation_id: operation.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: digest(&self.state).map_err(|_| AdapterError::Invalid)?,
            reason: "ROLLED_BACK".into(),
        };
        self.rollback_history
            .insert(operation.operation_id.clone(), (binding, receipt.clone()));
        Ok(receipt)
    }
    fn dry_run(&self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        validate_operation(o, now)?;
        if digest(&o.desired).map_err(|_| AdapterError::Invalid)? != o.desired_digest {
            return Err(AdapterError::Invalid);
        }
        Ok(AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: o.desired_digest.clone(),
            reason: "DRY_RUN_VALID".into(),
        })
    }
    fn verify(&self, o: &AdapterOperation) -> Result<AdapterReceipt, AdapterError> {
        let observed = digest(&self.state).map_err(|_| AdapterError::Invalid)?;
        Ok(AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: if observed == o.desired_digest {
                ConvergenceState::Converged
            } else {
                ConvergenceState::Failed
            },
            generation: self.generation,
            result_digest: observed,
            reason: "VERIFIED".into(),
        })
    }
}
pub struct RuntimeConfigAdapter {
    path: PathBuf,
    state_path: PathBuf,
    generation: u64,
    history: BTreeMap<String, (String, Vec<u8>, AdapterReceipt)>,
    rollback_history: BTreeMap<String, (String, AdapterReceipt)>,
    failure_injection: RuntimeConfigFailureInjection,
}
#[derive(Debug, Clone, Default)]
pub struct RuntimeConfigFailureInjection {
    pub interrupt_before_replace: bool,
    pub readback_mismatch: bool,
    pub rollback_failure: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RuntimeConfigAdapterState {
    generation: u64,
    history: BTreeMap<String, (String, Vec<u8>, AdapterReceipt)>,
    #[serde(default)]
    rollback_history: BTreeMap<String, (String, AdapterReceipt)>,
}
impl RuntimeConfigAdapter {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AdapterError> {
        let path = path.into();
        let state_path = path.with_extension("iicp-management-state.json");
        let state = if state_path.exists() {
            serde_json::from_slice::<RuntimeConfigAdapterState>(
                &fs::read(&state_path).map_err(|_| AdapterError::Io)?,
            )
            .map_err(|_| AdapterError::Invalid)?
        } else {
            RuntimeConfigAdapterState::default()
        };
        Ok(Self {
            path,
            state_path,
            generation: state.generation,
            history: state.history,
            rollback_history: state.rollback_history,
            failure_injection: RuntimeConfigFailureInjection::default(),
        })
    }
    pub fn with_failure_injection(mut self, injection: RuntimeConfigFailureInjection) -> Self {
        self.failure_injection = injection;
        self
    }
    fn validate(v: &Value) -> bool {
        if contains_secret(v) {
            return false;
        }
        serde_json::to_string(v)
            .ok()
            .and_then(|json| RuntimeConfigV1::from_json(&json).ok())
            .is_some_and(|config| config.validate().is_empty())
    }
    fn persist_state(&self) -> Result<(), AdapterError> {
        let state = RuntimeConfigAdapterState {
            generation: self.generation,
            history: self.history.clone(),
            rollback_history: self.rollback_history.clone(),
        };
        write_owner_only_atomic(&self.state_path, &state)
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
    fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            capabilities: vec!["runtime-config-v1".into()],
            actions: vec![
                "observe".into(),
                "dry_run".into(),
                "apply".into(),
                "verify".into(),
                "rollback".into(),
            ],
            permissions: vec![format!("file:read-write:{}", self.path.display())],
            outbound_only: true,
            resolves_secret_references: false,
        }
    }
    fn observe(&self) -> Result<Value, AdapterError> {
        serde_json::from_slice(&fs::read(&self.path).map_err(|_| AdapterError::Io)?)
            .map_err(|_| AdapterError::Invalid)
    }
    fn apply(&mut self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        if validate_operation(o, now).is_err() || !Self::validate(&o.desired) {
            return Err(AdapterError::Invalid);
        }
        let d = digest(&o.desired).map_err(|_| AdapterError::Invalid)?;
        if d != o.desired_digest {
            return Err(AdapterError::Invalid);
        }
        let binding = operation_binding(o)?;
        if let Some((prior, _, r)) = self.history.get(&o.operation_id) {
            return if prior == &binding {
                Ok(r.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if o.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let old = fs::read(&self.path).unwrap_or_default();
        let old_value: Value = serde_json::from_slice(&old).map_err(|_| AdapterError::Invalid)?;
        if !Self::validate(&old_value) {
            return Err(AdapterError::Invalid);
        }
        let parent = self.path.parent().ok_or(AdapterError::Io)?;
        let mut tmp = tempfile_in(parent).map_err(|_| AdapterError::Io)?;
        if serde_json::to_writer(&mut tmp.0, &o.desired).is_err()
            || tmp.0.flush().is_err()
            || tmp.0.sync_all().is_err()
        {
            let _ = fs::remove_file(&tmp.1);
            return Err(AdapterError::Io);
        }
        if self.failure_injection.interrupt_before_replace {
            let _ = fs::remove_file(&tmp.1);
            return Err(AdapterError::Io);
        }
        if fs::rename(&tmp.1, &self.path).is_err() {
            let _ = fs::remove_file(&tmp.1);
            return Err(AdapterError::Io);
        }
        if self.failure_injection.readback_mismatch || self.observe() != Ok(o.desired.clone()) {
            if self.failure_injection.rollback_failure
                || restore_owner_only(&self.path, &old).is_err()
            {
                return Ok(AdapterReceipt {
                    operation_id: o.operation_id.clone(),
                    state: ConvergenceState::PartiallyConverged,
                    generation: self.generation,
                    result_digest: digest(&self.observe().unwrap_or(Value::Null))
                        .map_err(|_| AdapterError::Invalid)?,
                    reason: "READBACK_MISMATCH_ROLLBACK_FAILED".into(),
                });
            }
            return Ok(AdapterReceipt {
                operation_id: o.operation_id.clone(),
                state: ConvergenceState::Failed,
                generation: self.generation,
                result_digest: digest(&self.observe().unwrap_or(Value::Null))
                    .map_err(|_| AdapterError::Invalid)?,
                reason: "READBACK_MISMATCH_ROLLED_BACK".into(),
            });
        }
        self.generation += 1;
        let r = AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: d.clone(),
            reason: "APPLIED".into(),
        };
        let prior_generation = self.generation - 1;
        self.history
            .insert(o.operation_id.clone(), (binding, old, r.clone()));
        if self.persist_state().is_err() {
            let (_, prior, _) = self
                .history
                .remove(&o.operation_id)
                .ok_or(AdapterError::Io)?;
            self.generation = prior_generation;
            restore_owner_only(&self.path, &prior)?;
            return Err(AdapterError::Io);
        }
        Ok(r)
    }
    fn rollback(&mut self, operation: &AdapterOperation) -> Result<AdapterReceipt, AdapterError> {
        let binding = operation_binding(operation)?;
        if let Some((prior, receipt)) = self.rollback_history.get(&operation.operation_id) {
            return if prior == &binding {
                Ok(receipt.clone())
            } else {
                Err(AdapterError::ReplayConflict)
            };
        }
        if operation.expected_generation != self.generation {
            return Err(AdapterError::Generation);
        }
        let id = operation
            .related_operation_id
            .as_deref()
            .ok_or(AdapterError::Invalid)?;
        let (_, old, _) = self
            .history
            .get(id)
            .cloned()
            .ok_or(AdapterError::Unsupported)?;
        let current = fs::read(&self.path).map_err(|_| AdapterError::Io)?;
        restore_owner_only(&self.path, &old)?;
        self.generation += 1;
        let receipt = AdapterReceipt {
            operation_id: operation.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: digest(&self.observe()?).map_err(|_| AdapterError::Invalid)?,
            reason: "ROLLED_BACK".into(),
        };
        self.rollback_history
            .insert(operation.operation_id.clone(), (binding, receipt.clone()));
        if self.persist_state().is_err() {
            self.rollback_history.remove(&operation.operation_id);
            self.generation -= 1;
            restore_owner_only(&self.path, &current)?;
            return Err(AdapterError::Io);
        }
        Ok(receipt)
    }
    fn dry_run(&self, o: &AdapterOperation, now: u64) -> Result<AdapterReceipt, AdapterError> {
        validate_operation(o, now)?;
        if !Self::validate(&o.desired)
            || digest(&o.desired).map_err(|_| AdapterError::Invalid)? != o.desired_digest
        {
            return Err(AdapterError::Invalid);
        }
        Ok(AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: ConvergenceState::Converged,
            generation: self.generation,
            result_digest: o.desired_digest.clone(),
            reason: "DRY_RUN_VALID".into(),
        })
    }
    fn verify(&self, o: &AdapterOperation) -> Result<AdapterReceipt, AdapterError> {
        let observed = digest(&self.observe()?).map_err(|_| AdapterError::Invalid)?;
        Ok(AdapterReceipt {
            operation_id: o.operation_id.clone(),
            state: if observed == o.desired_digest {
                ConvergenceState::Converged
            } else {
                ConvergenceState::Failed
            },
            generation: self.generation,
            result_digest: observed,
            reason: "VERIFIED".into(),
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

fn restore_owner_only(path: &Path, contents: &[u8]) -> Result<(), AdapterError> {
    let parent = path.parent().ok_or(AdapterError::Io)?;
    let mut stage = tempfile_in(parent).map_err(|_| AdapterError::Io)?;
    if stage.0.write_all(contents).is_err()
        || stage.0.flush().is_err()
        || stage.0.sync_all().is_err()
        || fs::rename(&stage.1, path).is_err()
    {
        let _ = fs::remove_file(stage.1);
        return Err(AdapterError::Io);
    }
    Ok(())
}

fn write_owner_only_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), AdapterError> {
    let parent = path.parent().ok_or(AdapterError::Io)?;
    let mut stage = tempfile_in(parent).map_err(|_| AdapterError::Io)?;
    if serde_json::to_writer(&mut stage.0, value).is_err()
        || stage.0.flush().is_err()
        || stage.0.sync_all().is_err()
        || fs::rename(&stage.1, path).is_err()
    {
        let _ = fs::remove_file(stage.1);
        return Err(AdapterError::Io);
    }
    Ok(())
}
