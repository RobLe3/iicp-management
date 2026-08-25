use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use thiserror::Error;

pub mod adapters;
pub mod apply_gate;
pub mod bootstrap;
pub mod controller;
pub mod diagnostics;
pub mod execution;
pub mod ipc;
pub mod policy_lifecycle;
pub mod profile;
pub mod progressive_authority;
pub mod reconciliation;
pub mod recovery;
pub mod rollout;
pub mod sandbox;
pub mod templates;
pub mod trial;

pub const CONTRACT_VERSION: &str = "1";
pub const PLANNER_VERSION: &str = "iicp-management-planner/0.1.0";
pub const POLICY_PROFILE: &str = "iicp.management-policy.typed-v0";
pub const MAX_POLICY_DEPTH: usize = 16;
pub const MAX_COLLECTION_VALUES: usize = 1024;
pub const MAX_POLICY_FUEL: usize = 50_000;
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
pub const MAX_POLICY_RULES: usize = 1_000;
pub const MAX_AST_NODES_PER_RULE: usize = 256;
pub const MAX_CONTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REFERENCE_DEPTH: usize = 16;
pub const MAX_POLICY_DURATION: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluationLimits {
    pub policy_bytes: usize,
    pub rules: usize,
    pub ast_nodes_per_rule: usize,
    pub expression_depth: usize,
    pub collection_values: usize,
    pub context_bytes: usize,
    pub reference_depth: usize,
    pub fuel: usize,
    pub wall_clock: Duration,
}

impl Default for EvaluationLimits {
    fn default() -> Self {
        Self {
            policy_bytes: MAX_POLICY_BYTES,
            rules: MAX_POLICY_RULES,
            ast_nodes_per_rule: MAX_AST_NODES_PER_RULE,
            expression_depth: MAX_POLICY_DEPTH,
            collection_values: MAX_COLLECTION_VALUES,
            context_bytes: MAX_CONTEXT_BYTES,
            reference_depth: MAX_REFERENCE_DEPTH,
            fuel: MAX_POLICY_FUEL,
            wall_clock: MAX_POLICY_DURATION,
        }
    }
}

impl EvaluationLimits {
    fn profile_compliant(self) -> bool {
        [
            (self.policy_bytes, MAX_POLICY_BYTES),
            (self.rules, MAX_POLICY_RULES),
            (self.ast_nodes_per_rule, MAX_AST_NODES_PER_RULE),
            (self.expression_depth, MAX_POLICY_DEPTH),
            (self.collection_values, MAX_COLLECTION_VALUES),
            (self.context_bytes, MAX_CONTEXT_BYTES),
            (self.reference_depth, MAX_REFERENCE_DEPTH),
            (self.fuel, MAX_POLICY_FUEL),
        ]
        .into_iter()
        .all(|(value, maximum)| value > 0 && value <= maximum)
            && self.wall_clock <= MAX_POLICY_DURATION
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DesiredStateBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub issuer: String,
    pub audience: String,
    pub expected_generation: u64,
    pub resources: Vec<ManagedResource>,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagedResource {
    pub resource_id: String,
    pub kind: String,
    pub desired: Value,
    #[serde(default)]
    pub secret_refs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExtensionClass {
    OptionalIgnorable,
    OptionalNegotiable,
    RequiredUnderstood,
    RequiredSecurityCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionRequirement {
    pub id: String,
    pub class: ExtensionClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedState {
    pub generation: u64,
    pub resource_digests: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: String,
    pub planner_version: String,
    pub bundle_id: String,
    pub bundle_digest: String,
    pub expected_generation: u64,
    pub target_generation: u64,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub operation_id: String,
    pub resource_id: String,
    pub action: String,
    pub before_digest: String,
    pub after_digest: String,
    pub expected_generation: u64,
    pub target_generation: u64,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub schema_version: String,
    pub approval_id: String,
    pub audience: String,
    pub bundle_digest: String,
    pub plan_digest: String,
    pub expected_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceState {
    Converged,
    PartiallyConverged,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: String,
    pub resource_id: String,
    pub observed_generation: u64,
    pub observed_digest: String,
    pub state: ConvergenceState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub audience: String,
    pub bundle_digest: String,
    pub plan_digest: String,
    pub accepted_generation: u64,
    pub effective_state: ConvergenceState,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    pub decision: PolicyDecision,
    pub reason_codes: Vec<String>,
    pub input_digest: String,
    pub policy_digest: String,
    pub evaluator_profile: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManagementError {
    #[error("SCHEMA_UNSUPPORTED_VERSION")]
    UnsupportedVersion,
    #[error("SEMANTIC_EMPTY_IDENTIFIER")]
    EmptyIdentifier,
    #[error("SEMANTIC_DUPLICATE_RESOURCE")]
    DuplicateResource,
    #[error("SECRET_INLINE_VALUE_FORBIDDEN")]
    InlineSecret,
    #[error("PROFILE_UNSUPPORTED_REQUIRED:{0}")]
    UnsupportedRequiredExtension(String),
    #[error("PLAN_STALE_GENERATION")]
    StaleGeneration,
    #[error("PLAN_APPROVAL_DIGEST_MISMATCH")]
    ApprovalDigestMismatch,
    #[error("AUTHZ_WRONG_AUDIENCE")]
    WrongAudience,
    #[error("PLAN_RESOURCE_LIMIT")]
    ResourceLimit,
    #[error("PLAN_CANCELLED")]
    Cancelled,
    #[error("RECEIPT_BINDING_MISMATCH")]
    ReceiptBindingMismatch,
    #[error("RECEIPT_EFFECTIVE_STATE_MISMATCH")]
    ReceiptStateMismatch,
    #[error("SCHEMA_SERIALIZATION")]
    Serialization,
}

pub fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect();
            Value::Object(Map::from_iter(sorted))
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

pub fn digest<T: Serialize>(value: &T) -> Result<String, ManagementError> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| ManagementError::Serialization)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn contains_inline_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "secret" | "secret_value" | "password" | "token" | "private_key"
            ) || contains_inline_secret(value)
        }),
        Value::Array(values) => values.iter().any(contains_inline_secret),
        _ => false,
    }
}

pub fn validate_bundle(
    bundle: &DesiredStateBundle,
    supported_extensions: &BTreeSet<String>,
    max_resources: usize,
) -> Result<(), ManagementError> {
    if bundle.schema_version != CONTRACT_VERSION {
        return Err(ManagementError::UnsupportedVersion);
    }
    if bundle.bundle_id.is_empty() || bundle.issuer.is_empty() || bundle.audience.is_empty() {
        return Err(ManagementError::EmptyIdentifier);
    }
    if bundle.resources.len() > max_resources {
        return Err(ManagementError::ResourceLimit);
    }
    let mut ids = BTreeSet::new();
    for resource in &bundle.resources {
        if resource.resource_id.is_empty() || resource.kind.is_empty() {
            return Err(ManagementError::EmptyIdentifier);
        }
        if !ids.insert(&resource.resource_id) {
            return Err(ManagementError::DuplicateResource);
        }
        if contains_inline_secret(&resource.desired) {
            return Err(ManagementError::InlineSecret);
        }
    }
    for extension in &bundle.extensions {
        if !supported_extensions.contains(&extension.id)
            && matches!(
                extension.class,
                ExtensionClass::RequiredUnderstood | ExtensionClass::RequiredSecurityCritical
            )
        {
            return Err(ManagementError::UnsupportedRequiredExtension(
                extension.id.clone(),
            ));
        }
    }
    Ok(())
}

pub fn plan(
    bundle: &DesiredStateBundle,
    accepted: &AcceptedState,
    supported_extensions: &BTreeSet<String>,
    max_resources: usize,
) -> Result<Plan, ManagementError> {
    plan_with_control(
        bundle,
        accepted,
        supported_extensions,
        PlanningControl {
            max_resources,
            cancelled: false,
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanningControl {
    pub max_resources: usize,
    pub cancelled: bool,
}

pub fn plan_with_control(
    bundle: &DesiredStateBundle,
    accepted: &AcceptedState,
    supported_extensions: &BTreeSet<String>,
    control: PlanningControl,
) -> Result<Plan, ManagementError> {
    if control.cancelled {
        return Err(ManagementError::Cancelled);
    }
    validate_bundle(bundle, supported_extensions, control.max_resources)?;
    if bundle.expected_generation != accepted.generation {
        return Err(ManagementError::StaleGeneration);
    }
    let mut normalized_bundle = bundle.clone();
    normalized_bundle
        .resources
        .sort_by(|a, b| a.resource_id.cmp(&b.resource_id));
    normalized_bundle.extensions.sort_by(|a, b| {
        let left = format!("{:?}:{}", a.class, a.id);
        let right = format!("{:?}:{}", b.class, b.id);
        left.cmp(&right)
    });
    let bundle_digest = digest(&normalized_bundle)?;
    let target_generation = accepted.generation + 1;
    let mut resources = bundle.resources.clone();
    resources.sort_by(|a, b| a.resource_id.cmp(&b.resource_id));
    let mut operations = Vec::with_capacity(resources.len());
    for (index, resource) in resources.iter().enumerate() {
        let after_digest = digest(&resource.desired)?;
        let before_digest = accepted
            .resource_digests
            .get(&resource.resource_id)
            .cloned()
            .unwrap_or_else(|| "absent".to_string());
        let action = if before_digest == "absent" {
            "create"
        } else {
            "update"
        };
        operations.push(Operation {
            operation_id: format!("op-{:04}", index + 1),
            resource_id: resource.resource_id.clone(),
            action: action.to_string(),
            before_digest,
            after_digest,
            expected_generation: accepted.generation,
            target_generation,
            idempotency_key: format!("{}:{}", bundle.bundle_id, resource.resource_id),
        });
    }
    Ok(Plan {
        schema_version: CONTRACT_VERSION.to_string(),
        planner_version: PLANNER_VERSION.to_string(),
        bundle_id: bundle.bundle_id.clone(),
        bundle_digest,
        expected_generation: accepted.generation,
        target_generation,
        operations,
    })
}

pub fn authorize_plan(
    approval: &Approval,
    plan: &Plan,
    local_audience: &str,
) -> Result<(), ManagementError> {
    if approval.audience != local_audience {
        return Err(ManagementError::WrongAudience);
    }
    if approval.expected_generation != plan.expected_generation
        || approval.bundle_digest != plan.bundle_digest
        || approval.plan_digest != digest(plan)?
    {
        return Err(ManagementError::ApprovalDigestMismatch);
    }
    Ok(())
}

pub fn derive_effective_state(observations: &[Observation]) -> ConvergenceState {
    let converged = observations
        .iter()
        .filter(|observation| observation.state == ConvergenceState::Converged)
        .count();
    let failed = observations
        .iter()
        .filter(|observation| observation.state == ConvergenceState::Failed)
        .count();
    if !observations.is_empty() && converged == observations.len() {
        ConvergenceState::Converged
    } else if observations.is_empty() || failed == observations.len() {
        ConvergenceState::Failed
    } else {
        ConvergenceState::PartiallyConverged
    }
}

fn observations_match_plan(receipt: &Receipt, plan: &Plan) -> bool {
    if receipt.observations.len() != plan.operations.len() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for observation in &receipt.observations {
        let Some(operation) = plan
            .operations
            .iter()
            .find(|operation| operation.resource_id == observation.resource_id)
        else {
            return false;
        };
        if observation.schema_version != CONTRACT_VERSION
            || observation.observed_generation != receipt.accepted_generation
            || !seen.insert(&observation.resource_id)
            || (observation.state == ConvergenceState::Converged
                && observation.observed_digest != operation.after_digest)
        {
            return false;
        }
    }
    true
}

pub fn verify_receipt(
    receipt: &Receipt,
    plan: &Plan,
    local_audience: &str,
) -> Result<(), ManagementError> {
    if receipt.schema_version != CONTRACT_VERSION
        || receipt.audience != local_audience
        || receipt.bundle_digest != plan.bundle_digest
        || receipt.plan_digest != digest(plan)?
        || receipt.accepted_generation != plan.target_generation
        || !observations_match_plan(receipt, plan)
    {
        return Err(ManagementError::ReceiptBindingMismatch);
    }
    if receipt.effective_state != derive_effective_state(&receipt.observations) {
        return Err(ManagementError::ReceiptStateMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Eval {
    True,
    False,
    Unknown,
    Stale,
    Invalid,
    Limit,
}

fn serialized_len(value: &Value) -> Result<usize, ManagementError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| ManagementError::Serialization)
}

fn validate_value_shape(
    value: &Value,
    limits: EvaluationLimits,
    depth: usize,
    nodes: &mut usize,
) -> Eval {
    if depth > limits.expression_depth {
        return Eval::Limit;
    }
    *nodes += 1;
    if *nodes > limits.ast_nodes_per_rule {
        return Eval::Limit;
    }
    match value {
        Value::Array(values) => {
            if values.len() > limits.collection_values {
                return Eval::Limit;
            }
            for item in values {
                let result = validate_value_shape(item, limits, depth + 1, nodes);
                if result != Eval::True {
                    return result;
                }
            }
        }
        Value::Object(values) => {
            for item in values.values() {
                let result = validate_value_shape(item, limits, depth + 1, nodes);
                if result != Eval::True {
                    return result;
                }
            }
        }
        _ => {}
    }
    Eval::True
}

fn validate_context_collections(value: &Value, limit: usize) -> Eval {
    match value {
        Value::Array(values) => {
            if values.len() > limit {
                return Eval::Limit;
            }
            for item in values {
                let result = validate_context_collections(item, limit);
                if result != Eval::True {
                    return result;
                }
            }
        }
        Value::Object(values) => {
            for item in values.values() {
                let result = validate_context_collections(item, limit);
                if result != Eval::True {
                    return result;
                }
            }
        }
        _ => {}
    }
    Eval::True
}

fn resolve_value(
    value: &Value,
    rules: &Map<String, Value>,
    limits: EvaluationLimits,
    stack: &mut Vec<String>,
) -> Result<Value, Eval> {
    if let Some(reference) = value
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("ref"))
        .and_then(Value::as_str)
    {
        if stack.iter().any(|item| item == reference) {
            return Err(Eval::Invalid);
        }
        if stack.len() >= limits.reference_depth {
            return Err(Eval::Limit);
        }
        let referenced = rules.get(reference).ok_or(Eval::Invalid)?;
        stack.push(reference.to_string());
        let resolved = resolve_value(referenced, rules, limits, stack);
        stack.pop();
        return resolved;
    }
    match value {
        Value::Array(values) => values
            .iter()
            .map(|item| resolve_value(item, rules, limits, stack))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, item)| {
                resolve_value(item, rules, limits, stack).map(|value| (key.clone(), value))
            })
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        _ => Ok(value.clone()),
    }
}

fn prepare_policy(policy: &Value, limits: EvaluationLimits) -> Result<Value, Eval> {
    let has_rules = policy.get("rules").is_some();
    let has_entry = policy.get("entry").is_some();
    if has_rules != has_entry {
        return Err(Eval::Invalid);
    }
    if !has_rules {
        let mut nodes = 0;
        let result = validate_value_shape(policy, limits, 0, &mut nodes);
        return if result == Eval::True {
            Ok(policy.clone())
        } else {
            Err(result)
        };
    }
    let rules = policy
        .get("rules")
        .and_then(Value::as_object)
        .ok_or(Eval::Invalid)?;
    if rules.len() > limits.rules {
        return Err(Eval::Limit);
    }
    for rule in rules.values() {
        let mut nodes = 0;
        let result = validate_value_shape(rule, limits, 0, &mut nodes);
        if result != Eval::True {
            return Err(result);
        }
    }
    let entry = policy.get("entry").ok_or(Eval::Invalid)?;
    let resolved = resolve_value(entry, rules, limits, &mut Vec::new())?;
    let mut nodes = 0;
    let result = validate_value_shape(&resolved, limits, 0, &mut nodes);
    if result == Eval::True {
        Ok(resolved)
    } else {
        Err(result)
    }
}

fn validate_policy_inputs(
    context: &Value,
    policy: &Value,
    limits: EvaluationLimits,
) -> Result<Value, Eval> {
    if !limits.profile_compliant() {
        return Err(Eval::Invalid);
    }
    if serialized_len(policy).map_err(|_| Eval::Invalid)? > limits.policy_bytes
        || serialized_len(context).map_err(|_| Eval::Invalid)? > limits.context_bytes
    {
        return Err(Eval::Limit);
    }
    let context_shape = validate_context_collections(context, limits.collection_values);
    if context_shape != Eval::True {
        return Err(context_shape);
    }
    prepare_policy(policy, limits)
}

fn context_value<'a>(context: &'a Value, name: &str) -> Option<&'a Value> {
    context.as_object()?.get(name)
}

fn eval_all(
    items: &[Value],
    context: &Value,
    depth: usize,
    fuel: &mut usize,
    limits: EvaluationLimits,
) -> Eval {
    let mut result = Eval::True;
    for item in items {
        match eval_expr(item, context, depth + 1, fuel, limits) {
            Eval::True => {}
            Eval::False => result = Eval::False,
            other => return other,
        }
    }
    result
}

fn eval_any(
    items: &[Value],
    context: &Value,
    depth: usize,
    fuel: &mut usize,
    limits: EvaluationLimits,
) -> Eval {
    let mut saw_unknown = false;
    for item in items {
        match eval_expr(item, context, depth + 1, fuel, limits) {
            Eval::True => return Eval::True,
            Eval::False => {}
            Eval::Unknown => saw_unknown = true,
            other => return other,
        }
    }
    if saw_unknown {
        Eval::Unknown
    } else {
        Eval::False
    }
}

fn eval_binary(operator: &str, arguments: &[Value], context: &Value) -> Eval {
    if arguments.len() != 2 {
        return Eval::Invalid;
    }
    let Some(name) = arguments[0].as_str() else {
        return Eval::Invalid;
    };
    let Some(actual) = context_value(context, name) else {
        return Eval::Unknown;
    };
    if actual.is_null() {
        return Eval::Unknown;
    }
    match operator {
        "eq" => Eval::from(actual == &arguments[1]),
        "lte" => eval_lte(name, actual, &arguments[1]),
        "in" => eval_in(actual, &arguments[1]),
        "contains" => eval_contains(actual, &arguments[1]),
        _ => Eval::Invalid,
    }
}

fn eval_lte(name: &str, actual: &Value, expected: &Value) -> Eval {
    match (actual.as_f64(), expected.as_f64()) {
        (Some(left), Some(right)) if left <= right => Eval::True,
        (Some(_), Some(_)) if name.contains("evidence_age") => Eval::Stale,
        (Some(_), Some(_)) => Eval::False,
        _ => Eval::Invalid,
    }
}

fn eval_in(actual: &Value, expected: &Value) -> Eval {
    match expected.as_array() {
        Some(_) if actual.is_array() || actual.is_object() => Eval::Invalid,
        Some(values) if values.len() <= MAX_COLLECTION_VALUES => {
            Eval::from(values.contains(actual))
        }
        Some(_) => Eval::Limit,
        None => Eval::Invalid,
    }
}

fn eval_contains(actual: &Value, expected: &Value) -> Eval {
    match actual.as_array() {
        Some(values) if values.len() <= MAX_COLLECTION_VALUES => {
            Eval::from(values.contains(expected))
        }
        Some(_) => Eval::Limit,
        None => Eval::Invalid,
    }
}

impl From<bool> for Eval {
    fn from(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }
}

fn eval_generated(
    object: &Map<String, Value>,
    context: &Value,
    limits: EvaluationLimits,
) -> Option<Eval> {
    if let Some(generated) = object.get("generated_nesting").and_then(Value::as_u64) {
        return Some(if generated as usize > limits.expression_depth {
            Eval::Limit
        } else {
            Eval::True
        });
    }
    if object.contains_key("all_values_must_be_true") {
        let size = context
            .get("generated_collection_size")
            .and_then(Value::as_u64)
            .unwrap_or_default() as usize;
        return Some(if size > limits.collection_values {
            Eval::Limit
        } else {
            Eval::True
        });
    }
    object
        .contains_key("evaluate_generated_operations")
        .then(|| {
            let operations = context
                .get("generated_operations")
                .and_then(Value::as_u64)
                .unwrap_or_default() as usize;
            if operations > limits.fuel {
                Eval::Limit
            } else {
                Eval::True
            }
        })
}

fn eval_compound(
    object: &Map<String, Value>,
    context: &Value,
    depth: usize,
    fuel: &mut usize,
    limits: EvaluationLimits,
) -> Option<Eval> {
    if let Some(items) = object.get("all").and_then(Value::as_array) {
        return Some(eval_all(items, context, depth, fuel, limits));
    }
    object
        .get("any")
        .and_then(Value::as_array)
        .map(|items| eval_any(items, context, depth, fuel, limits))
}

fn eval_known_binary(object: &Map<String, Value>, context: &Value) -> Option<Eval> {
    ["eq", "lte", "in", "contains"].iter().find_map(|operator| {
        object
            .get(*operator)
            .and_then(Value::as_array)
            .map(|arguments| eval_binary(operator, arguments, context))
    })
}

fn eval_expr(
    expr: &Value,
    context: &Value,
    depth: usize,
    fuel: &mut usize,
    limits: EvaluationLimits,
) -> Eval {
    if depth > limits.expression_depth || *fuel == 0 {
        return Eval::Limit;
    }
    *fuel -= 1;
    let Some(object) = expr.as_object() else {
        return Eval::Invalid;
    };
    if let Some(result) = eval_generated(object, context, limits) {
        return result;
    }
    if let Some(result) = eval_compound(object, context, depth, fuel, limits) {
        return result;
    }
    eval_known_binary(object, context).unwrap_or(Eval::Invalid)
}

fn evaluate_adapter(context: &Value, policy: &Value) -> Option<(Eval, &'static str)> {
    policy.get("require_adapter_allow")?;
    Some(
        if context.get("adapter_result").and_then(Value::as_str) == Some("allow") {
            (Eval::True, "IICP-POLICY-ALLOW")
        } else {
            (Eval::Invalid, "IICP-POLICY-ADAPTER-ERROR")
        },
    )
}

fn evaluate_evidence_time(context: &Value, policy: &Value) -> Option<Eval> {
    policy.get("evidence_valid_at")?;
    Some(
        match (
            context.get("evaluated_at").and_then(Value::as_str),
            context.get("evidence_expires_at").and_then(Value::as_str),
        ) {
            (Some(now), Some(expires)) if now <= expires => Eval::True,
            (Some(_), Some(_)) => Eval::Stale,
            _ => Eval::Unknown,
        },
    )
}

fn apply_authority_denied(context: &Value, policy: &Value) -> bool {
    policy.get("action").and_then(Value::as_str) == Some("apply")
        && policy.get("requires_authority").and_then(Value::as_bool) == Some(true)
        && context.get("apply_authority").and_then(Value::as_bool) != Some(true)
}

fn evaluate_allow_deny(context: &Value, policy: &Value, limits: EvaluationLimits) -> Option<Eval> {
    let (allow, deny) = (policy.get("allow")?, policy.get("deny")?);
    let mut fuel = limits.fuel;
    match eval_expr(deny, context, 0, &mut fuel, limits) {
        Eval::True => Some(Eval::False),
        Eval::False => Some(eval_expr(allow, context, 0, &mut fuel, limits)),
        other => Some(other),
    }
}

fn explicit_deny_matches(context: &Value, policy: &Value, limits: EvaluationLimits) -> bool {
    let Some(deny) = policy.get("deny") else {
        return false;
    };
    let mut fuel = limits.fuel;
    eval_expr(deny, context, 0, &mut fuel, limits) == Eval::True
}

fn preflight_policy(
    context: &Value,
    policy: &Value,
    limits: EvaluationLimits,
) -> Option<(PolicyDecision, &'static str)> {
    if let Some((result, reason)) = evaluate_adapter(context, policy) {
        let decision = if result == Eval::True {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Indeterminate
        };
        return Some((decision, reason));
    }
    if apply_authority_denied(context, policy) {
        return Some((PolicyDecision::Deny, "IICP-POLICY-AUTHORITY-DENIED"));
    }
    if policy.get("allow").is_some() && explicit_deny_matches(context, policy, limits) {
        return Some((PolicyDecision::Deny, "IICP-POLICY-EXPLICIT-DENY"));
    }
    None
}

fn evaluate_policy_body(context: &Value, policy: &Value, limits: EvaluationLimits) -> Eval {
    if let Some(result) = evaluate_evidence_time(context, policy) {
        return result;
    }
    if let Some(result) = evaluate_allow_deny(context, policy, limits) {
        return result;
    }
    let mut fuel = limits.fuel;
    eval_expr(policy, context, 0, &mut fuel, limits)
}

fn eval_disposition(result: Eval) -> (PolicyDecision, &'static str) {
    match result {
        Eval::True => (PolicyDecision::Allow, "IICP-POLICY-ALLOW"),
        Eval::False => (PolicyDecision::Deny, "IICP-POLICY-DEFAULT-DENY"),
        Eval::Unknown => (
            PolicyDecision::Indeterminate,
            "IICP-POLICY-EVIDENCE-UNKNOWN",
        ),
        Eval::Stale => (PolicyDecision::Deny, "IICP-POLICY-EVIDENCE-STALE"),
        Eval::Invalid => (PolicyDecision::Indeterminate, "IICP-POLICY-INPUT-INVALID"),
        Eval::Limit => (PolicyDecision::Indeterminate, "IICP-POLICY-LIMIT-EXCEEDED"),
    }
}

pub fn evaluate_policy(context: &Value, policy: &Value) -> Result<PolicyResult, ManagementError> {
    evaluate_policy_with_limits(context, policy, EvaluationLimits::default())
}

pub fn evaluate_policy_with_limits(
    context: &Value,
    policy: &Value,
    limits: EvaluationLimits,
) -> Result<PolicyResult, ManagementError> {
    let started = Instant::now();
    let input_digest = digest(context)?;
    let policy_digest = digest(policy)?;
    let prepared = match validate_policy_inputs(context, policy, limits) {
        Ok(prepared) => prepared,
        Err(result) => {
            let (decision, reason) = eval_disposition(result);
            return Ok(policy_result(decision, reason, input_digest, policy_digest));
        }
    };
    if let Some((decision, reason)) = preflight_policy(context, &prepared, limits) {
        return Ok(policy_result(decision, reason, input_digest, policy_digest));
    }
    let evaluated = evaluate_policy_body(context, &prepared, limits);
    let result = if started.elapsed() > limits.wall_clock {
        Eval::Limit
    } else {
        evaluated
    };
    let (decision, reason) = eval_disposition(result);
    Ok(policy_result(decision, reason, input_digest, policy_digest))
}

fn policy_result(
    decision: PolicyDecision,
    reason: &str,
    input_digest: String,
    policy_digest: String,
) -> PolicyResult {
    PolicyResult {
        decision,
        reason_codes: vec![reason.to_string()],
        input_digest,
        policy_digest,
        evaluator_profile: POLICY_PROFILE.to_string(),
    }
}

pub mod completion;
