//! Process-local enforcement of an active Management policy through `IicpClient`.
//!
//! Management projects only hard constraints it can represent without loss.
//! The Rust client continues to own discovery, native safety checks, ranking,
//! retries, tickets, and provider dispatch.

use crate::digest;
use crate::policy_lifecycle::{InMemoryPolicyRepository, PolicyDisposition, PolicyRepository};
use iicp_client::{
    resolved_policy, CandidateRanker, ClientConfig, IicpClient, IicpError, RoutingPolicy,
    RoutingProfile, TaskRequest, TaskResponse, ROUTING_POLICY_REFUSAL_CODE,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use thiserror::Error;

pub const ROUTING_ENFORCEMENT_SCHEMA: &str = "iicp.management-routing-enforcement.v1";
pub const ROUTING_CANDIDATE_EVIDENCE_SCHEMA: &str = "iicp.management-routing-candidate-evidence.v1";
pub const MAX_ROUTING_PROJECTION_TTL_SECONDS: u64 = 300;

/// Content-free binding to the candidate evidence Management used when it
/// projected the active policy. Candidate references use the Rust client's
/// existing opaque candidate-reference algorithm; full node identifiers and
/// endpoints are not retained.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingCandidateEvidenceV1 {
    pub schema_version: String,
    pub evidence_source: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub eligible_candidate_refs: Vec<String>,
    pub ineligible_count: u64,
    pub unresolved_count: u64,
}

/// A bounded projection of one active Management policy generation into the
/// client-owned routing-policy boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingEnforcementProjectionV1 {
    pub schema_version: String,
    pub application_id: String,
    pub binding_id: String,
    pub binding_digest: String,
    pub policy_generation: u64,
    pub effective_policy_digest: String,
    pub candidate_evidence_digest: String,
    pub routing_policy_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub deny_all: bool,
    pub candidate_evidence: RoutingCandidateEvidenceV1,
    pub routing_policy: RoutingPolicy,
}

#[derive(Debug, Error)]
pub enum RoutingEnforcementError {
    #[error("ROUTING_ENFORCEMENT_INACTIVE")]
    Inactive,
    #[error("ROUTING_ENFORCEMENT_EXPIRED")]
    Expired,
    #[error("ROUTING_ENFORCEMENT_INVALID_VALIDITY")]
    InvalidValidity,
    #[error("ROUTING_ENFORCEMENT_EMPTY_POLICY")]
    EmptyPolicy,
    #[error("ROUTING_ENFORCEMENT_CANDIDATE_EVIDENCE_INVALID")]
    CandidateEvidenceInvalid,
    #[error("ROUTING_ENFORCEMENT_CANDIDATE_EVIDENCE_STALE")]
    CandidateEvidenceStale,
    #[error("ROUTING_ENFORCEMENT_CANDIDATE_EVIDENCE_UNRESOLVED")]
    CandidateEvidenceUnresolved,
    #[error("ROUTING_ENFORCEMENT_UNSUPPORTED_POLICY")]
    UnsupportedPolicy,
    #[error("ROUTING_ENFORCEMENT_DIGEST_MISMATCH")]
    DigestMismatch,
    #[error("ROUTING_ENFORCEMENT_CLIENT:{0}")]
    Client(#[from] IicpError),
}

#[derive(Debug, Default)]
struct ProjectionAccumulator {
    allowed_regions: Option<BTreeSet<String>>,
    require_encryption: bool,
    require_policy_manifest: bool,
    require_no_payload_retention: bool,
    allow_remote_executor: bool,
    identity_level: Option<String>,
    rule_count: usize,
    deny_all: bool,
}

impl ProjectionAccumulator {
    fn new() -> Self {
        Self {
            allow_remote_executor: true,
            ..Self::default()
        }
    }

    fn routing_policy(&self) -> RoutingPolicy {
        RoutingPolicy {
            profile: RoutingProfile::Standard,
            allowed_regions: self
                .allowed_regions
                .as_ref()
                .map(|regions| regions.iter().cloned().collect())
                .unwrap_or_default(),
            require_encryption: self.require_encryption.then_some(true),
            require_policy_manifest: self.require_policy_manifest.then_some(true),
            require_no_payload_retention: self.require_no_payload_retention.then_some(true),
            allow_remote_executor: (!self.allow_remote_executor).then_some(false),
            known_operator_only: (self.identity_level.as_deref() == Some("known_operator"))
                .then_some(true),
            required_manifest_identity_level: self.identity_level.clone(),
        }
    }
}

/// A client wrapper that revalidates the active Management generation before
/// every dispatch and intersects request-local policy with the enforced baseline.
pub struct ManagedIicpClient {
    inner: IicpClient,
    projection: RoutingEnforcementProjectionV1,
    baseline_policy: RoutingPolicy,
    baseline_deny_all: bool,
    delegated_ranker: Arc<RwLock<Option<Arc<dyn CandidateRanker>>>>,
}

struct EnforcementRanker {
    eligible_candidate_refs: BTreeSet<String>,
    delegated_ranker: Arc<RwLock<Option<Arc<dyn CandidateRanker>>>>,
}

impl CandidateRanker for EnforcementRanker {
    fn rank(
        &self,
        request: &iicp_client::RankerRequest<'_>,
        candidates: &[iicp_client::CandidateEvidenceV0],
    ) -> Result<Option<iicp_client::RankerDecision>, String> {
        if candidates.iter().any(|candidate| {
            !self
                .eligible_candidate_refs
                .contains(&candidate.candidate_ref)
        }) {
            return Err(
                "active Management evidence did not authorize every eligible candidate".into(),
            );
        }
        self.delegated_ranker
            .read()
            .map_err(|_| "active Management ranker state is unavailable".to_string())?
            .as_ref()
            .map_or(Ok(None), |ranker| ranker.rank(request, candidates))
    }
}

impl ManagedIicpClient {
    pub fn new(
        repository: &InMemoryPolicyRepository,
        projection: RoutingEnforcementProjectionV1,
        mut config: ClientConfig,
        now: u64,
    ) -> Result<Self, RoutingEnforcementError> {
        verify_routing_enforcement_projection(repository, &projection, now)?;
        let (baseline_policy, policy_denies_all) =
            intersect_routing_policies(&config.routing_policy, &projection.routing_policy);
        let baseline_deny_all = projection.deny_all || policy_denies_all;
        config.routing_policy = baseline_policy.clone();
        let delegated_ranker = Arc::new(RwLock::new(None));
        let enforcement_ranker = EnforcementRanker {
            eligible_candidate_refs: projection
                .candidate_evidence
                .eligible_candidate_refs
                .iter()
                .cloned()
                .collect(),
            delegated_ranker: delegated_ranker.clone(),
        };
        let inner = IicpClient::new(config)?.with_candidate_ranker(Arc::new(enforcement_ranker));
        Ok(Self {
            inner,
            projection,
            baseline_policy,
            baseline_deny_all,
            delegated_ranker,
        })
    }

    pub fn with_candidate_ranker(self, ranker: Arc<dyn CandidateRanker>) -> Self {
        *self
            .delegated_ranker
            .write()
            .expect("delegated ranker lock poisoned before publication") = Some(ranker);
        self
    }

    pub fn projection(&self) -> &RoutingEnforcementProjectionV1 {
        &self.projection
    }

    pub async fn submit(
        &self,
        repository: &InMemoryPolicyRepository,
        mut request: TaskRequest,
        now: u64,
    ) -> Result<TaskResponse, RoutingEnforcementError> {
        verify_routing_enforcement_projection(repository, &self.projection, now)?;
        let (request_policy, request_denies_all) = match request.routing_policy.as_ref() {
            Some(policy) => intersect_routing_policies(&self.baseline_policy, policy),
            None => (self.baseline_policy.clone(), false),
        };
        if self.baseline_deny_all || request_denies_all {
            return Err(routing_refusal().into());
        }
        request.routing_policy = Some(request_policy);
        self.inner.submit(request).await.map_err(Into::into)
    }
}

/// Derive the exact opaque candidate reference exposed by `iicp-client` v0
/// candidate evidence without retaining the input node identifier.
pub fn routing_candidate_ref(node_id: &str) -> Result<String, RoutingEnforcementError> {
    if node_id.trim().is_empty() || node_id.len() > 1024 {
        return Err(RoutingEnforcementError::CandidateEvidenceInvalid);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"iicp:candidate:v0\n");
    hasher.update(node_id.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

pub fn project_active_routing_policy(
    repository: &InMemoryPolicyRepository,
    binding_id: &str,
    candidate_evidence: &RoutingCandidateEvidenceV1,
    issued_at: u64,
    expires_at: u64,
) -> Result<RoutingEnforcementProjectionV1, RoutingEnforcementError> {
    if expires_at <= issued_at
        || expires_at.saturating_sub(issued_at) > MAX_ROUTING_PROJECTION_TTL_SECONDS
    {
        return Err(RoutingEnforcementError::InvalidValidity);
    }
    validate_candidate_evidence(candidate_evidence, issued_at, expires_at)?;
    let binding = repository
        .binding(binding_id)
        .ok_or(RoutingEnforcementError::Inactive)?;
    if binding.valid_from.is_some_and(|start| issued_at < start)
        || binding
            .valid_until
            .is_some_and(|end| issued_at >= end || expires_at > end)
    {
        return Err(RoutingEnforcementError::Expired);
    }
    let activation = repository
        .active(binding_id)
        .ok_or(RoutingEnforcementError::Inactive)?;
    if activation.activated_at > issued_at
        || activation
            .valid_until
            .is_some_and(|end| issued_at >= end || expires_at > end)
    {
        return Err(RoutingEnforcementError::Expired);
    }
    let binding_digest = digest(binding).map_err(|_| RoutingEnforcementError::DigestMismatch)?;
    if binding_digest != activation.binding_digest {
        return Err(RoutingEnforcementError::DigestMismatch);
    }

    let sources = repository
        .sources_for_binding(binding)
        .map_err(|_| RoutingEnforcementError::DigestMismatch)?;
    if sources.is_empty() {
        return Err(RoutingEnforcementError::EmptyPolicy);
    }
    let mut accumulator = ProjectionAccumulator::new();
    for (_, revision) in &sources {
        if matches!(
            revision.disposition,
            PolicyDisposition::Invalid | PolicyDisposition::Archived
        ) || revision.valid_from.is_some_and(|start| issued_at < start)
            || revision
                .valid_until
                .is_some_and(|end| issued_at >= end || expires_at > end)
        {
            return Err(RoutingEnforcementError::Expired);
        }
        project_expression(&revision.policy, &mut accumulator)?;
    }
    if accumulator.rule_count == 0 {
        return Err(RoutingEnforcementError::EmptyPolicy);
    }

    let routing_policy = accumulator.routing_policy();
    let effective_policy_digest = digest(&json!({
        "binding_digest": binding_digest,
        "policy_revision_digests": activation.policy_revision_digests,
        "policy_generation": activation.target_generation,
    }))
    .map_err(|_| RoutingEnforcementError::DigestMismatch)?;
    let candidate_evidence_digest =
        digest(candidate_evidence).map_err(|_| RoutingEnforcementError::DigestMismatch)?;
    let routing_policy_digest = routing_digest(
        &routing_policy,
        accumulator.deny_all || candidate_evidence.eligible_candidate_refs.is_empty(),
        &binding_digest,
        &candidate_evidence_digest,
        activation.target_generation,
        issued_at,
        expires_at,
    )?;
    Ok(RoutingEnforcementProjectionV1 {
        schema_version: ROUTING_ENFORCEMENT_SCHEMA.into(),
        application_id: binding.application_id.clone(),
        binding_id: binding.binding_id.clone(),
        binding_digest,
        policy_generation: activation.target_generation,
        effective_policy_digest,
        candidate_evidence_digest,
        routing_policy_digest,
        issued_at,
        expires_at,
        deny_all: accumulator.deny_all || candidate_evidence.eligible_candidate_refs.is_empty(),
        candidate_evidence: candidate_evidence.clone(),
        routing_policy,
    })
}

pub fn verify_routing_enforcement_projection(
    repository: &InMemoryPolicyRepository,
    projection: &RoutingEnforcementProjectionV1,
    now: u64,
) -> Result<(), RoutingEnforcementError> {
    if projection.schema_version != ROUTING_ENFORCEMENT_SCHEMA {
        return Err(RoutingEnforcementError::UnsupportedPolicy);
    }
    if now < projection.issued_at || now >= projection.expires_at {
        return Err(RoutingEnforcementError::Expired);
    }
    let expected = project_active_routing_policy(
        repository,
        &projection.binding_id,
        &projection.candidate_evidence,
        projection.issued_at,
        projection.expires_at,
    )?;
    let matches = projection.application_id == expected.application_id
        && projection.binding_digest == expected.binding_digest
        && projection.policy_generation == expected.policy_generation
        && projection.effective_policy_digest == expected.effective_policy_digest
        && projection.candidate_evidence_digest == expected.candidate_evidence_digest
        && projection.routing_policy_digest == expected.routing_policy_digest
        && projection.deny_all == expected.deny_all
        && routing_digest(
            &projection.routing_policy,
            projection.deny_all,
            &projection.binding_digest,
            &projection.candidate_evidence_digest,
            projection.policy_generation,
            projection.issued_at,
            projection.expires_at,
        )? == expected.routing_policy_digest;
    if !matches {
        return Err(RoutingEnforcementError::DigestMismatch);
    }
    Ok(())
}

fn validate_candidate_evidence(
    evidence: &RoutingCandidateEvidenceV1,
    issued_at: u64,
    projection_expires_at: u64,
) -> Result<(), RoutingEnforcementError> {
    if issued_at >= evidence.expires_at {
        return Err(RoutingEnforcementError::CandidateEvidenceStale);
    }
    if evidence.schema_version != ROUTING_CANDIDATE_EVIDENCE_SCHEMA
        || evidence.evidence_source.trim().is_empty()
        || evidence.evidence_source.len() > 128
        || !evidence
            .evidence_source
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !evidence.evidence_source.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
        || evidence.observed_at > issued_at
        || evidence.observed_at >= evidence.expires_at
        || evidence.expires_at < projection_expires_at
        || evidence.expires_at.saturating_sub(evidence.observed_at)
            > MAX_ROUTING_PROJECTION_TTL_SECONDS
        || evidence.eligible_candidate_refs.len() > 10_000
    {
        return Err(RoutingEnforcementError::CandidateEvidenceInvalid);
    }
    if evidence.unresolved_count > 0 {
        return Err(RoutingEnforcementError::CandidateEvidenceUnresolved);
    }
    let mut references = BTreeSet::new();
    for candidate_ref in &evidence.eligible_candidate_refs {
        if candidate_ref.len() != 64
            || !candidate_ref
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !references.insert(candidate_ref.as_str())
        {
            return Err(RoutingEnforcementError::CandidateEvidenceInvalid);
        }
    }
    Ok(())
}

fn project_expression(
    expression: &Value,
    accumulator: &mut ProjectionAccumulator,
) -> Result<(), RoutingEnforcementError> {
    let object = expression
        .as_object()
        .ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
    if object.len() != 1 {
        return Err(RoutingEnforcementError::UnsupportedPolicy);
    }
    if let Some(items) = object.get("all").and_then(Value::as_array) {
        if items.is_empty() {
            return Err(RoutingEnforcementError::EmptyPolicy);
        }
        for item in items {
            project_expression(item, accumulator)?;
        }
        return Ok(());
    }
    if let Some(arguments) = object.get("eq").and_then(Value::as_array) {
        return project_eq(arguments, accumulator);
    }
    if let Some(arguments) = object.get("in").and_then(Value::as_array) {
        return project_in(arguments, accumulator);
    }
    Err(RoutingEnforcementError::UnsupportedPolicy)
}

fn project_eq(
    arguments: &[Value],
    accumulator: &mut ProjectionAccumulator,
) -> Result<(), RoutingEnforcementError> {
    if arguments.len() != 2 {
        return Err(RoutingEnforcementError::UnsupportedPolicy);
    }
    let fact = arguments[0]
        .as_str()
        .ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
    accumulator.rule_count += 1;
    match fact {
        "region" => apply_regions(
            [region_value(&arguments[1])?].into_iter().collect(),
            accumulator,
        ),
        "remote_execution" if arguments[1] == Value::Bool(false) => {
            accumulator.allow_remote_executor = false;
            Ok(())
        }
        "retention_mode" if arguments[1].as_str() == Some("none") => {
            accumulator.require_no_payload_retention = true;
            Ok(())
        }
        "encryption_available" if arguments[1] == Value::Bool(true) => {
            accumulator.require_encryption = true;
            Ok(())
        }
        "policy_manifest_present" if arguments[1] == Value::Bool(true) => {
            accumulator.require_policy_manifest = true;
            Ok(())
        }
        "manifest_identity_level" => {
            let level = arguments[1]
                .as_str()
                .ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
            apply_identity(level, accumulator)
        }
        _ => Err(RoutingEnforcementError::UnsupportedPolicy),
    }
}

fn project_in(
    arguments: &[Value],
    accumulator: &mut ProjectionAccumulator,
) -> Result<(), RoutingEnforcementError> {
    if arguments.len() != 2 || arguments[0].as_str() != Some("region") {
        return Err(RoutingEnforcementError::UnsupportedPolicy);
    }
    let values = arguments[1]
        .as_array()
        .ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
    if values.is_empty() || values.len() > 64 {
        return Err(RoutingEnforcementError::UnsupportedPolicy);
    }
    let regions = values
        .iter()
        .map(region_value)
        .collect::<Result<BTreeSet<_>, _>>()?;
    accumulator.rule_count += 1;
    apply_regions(regions, accumulator)
}

fn region_value(value: &Value) -> Result<String, RoutingEnforcementError> {
    let value = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
    Ok(value.to_ascii_lowercase())
}

fn apply_regions(
    regions: BTreeSet<String>,
    accumulator: &mut ProjectionAccumulator,
) -> Result<(), RoutingEnforcementError> {
    let next = match accumulator.allowed_regions.take() {
        None => regions,
        Some(current) => current.intersection(&regions).cloned().collect(),
    };
    if next.is_empty() {
        accumulator.deny_all = true;
    }
    accumulator.allowed_regions = Some(next);
    Ok(())
}

fn identity_rank(level: &str) -> Option<u8> {
    match level {
        "signed_valid" => Some(1),
        "operator_bound" => Some(2),
        "known_operator" => Some(3),
        _ => None,
    }
}

fn apply_identity(
    level: &str,
    accumulator: &mut ProjectionAccumulator,
) -> Result<(), RoutingEnforcementError> {
    let rank = identity_rank(level).ok_or(RoutingEnforcementError::UnsupportedPolicy)?;
    if accumulator
        .identity_level
        .as_deref()
        .and_then(identity_rank)
        .is_none_or(|current| rank > current)
    {
        accumulator.identity_level = Some(level.to_string());
    }
    accumulator.require_policy_manifest = true;
    Ok(())
}

fn routing_digest(
    policy: &RoutingPolicy,
    deny_all: bool,
    binding_digest: &str,
    candidate_evidence_digest: &str,
    policy_generation: u64,
    issued_at: u64,
    expires_at: u64,
) -> Result<String, RoutingEnforcementError> {
    digest(&json!({
        "routing_policy": policy,
        "deny_all": deny_all,
        "binding_digest": binding_digest,
        "candidate_evidence_digest": candidate_evidence_digest,
        "policy_generation": policy_generation,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }))
    .map_err(|_| RoutingEnforcementError::DigestMismatch)
}

fn intersect_routing_policies(
    left: &RoutingPolicy,
    right: &RoutingPolicy,
) -> (RoutingPolicy, bool) {
    let left = resolved_policy(Some(left));
    let right = resolved_policy(Some(right));
    let left_regions_restricted = !left.allowed_regions.is_empty();
    let right_regions_restricted = !right.allowed_regions.is_empty();
    let left_regions = left
        .allowed_regions
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let right_regions = right
        .allowed_regions
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let regions = if left_regions.is_empty() {
        right_regions
    } else if right_regions.is_empty() {
        left_regions
    } else {
        left_regions.intersection(&right_regions).cloned().collect()
    };
    let deny_all = left_regions_restricted && right_regions_restricted && regions.is_empty();
    let identity_level = [
        left.required_manifest_identity_level.as_deref(),
        right.required_manifest_identity_level.as_deref(),
        left.known_operator_only.then_some("known_operator"),
        right.known_operator_only.then_some("known_operator"),
    ]
    .into_iter()
    .flatten()
    .max_by_key(|value| identity_rank(value).unwrap_or(3))
    .map(str::to_owned);
    (
        RoutingPolicy {
            profile: RoutingProfile::Standard,
            allowed_regions: regions.into_iter().collect(),
            require_encryption: Some(left.require_encryption || right.require_encryption),
            require_policy_manifest: Some(
                left.require_policy_manifest
                    || right.require_policy_manifest
                    || identity_level.is_some(),
            ),
            require_no_payload_retention: Some(
                left.require_no_payload_retention || right.require_no_payload_retention,
            ),
            allow_remote_executor: Some(left.allow_remote_executor && right.allow_remote_executor),
            known_operator_only: Some(identity_level.as_deref() == Some("known_operator")),
            required_manifest_identity_level: identity_level,
        },
        deny_all,
    )
}

fn routing_refusal() -> IicpError {
    IicpError::PolicyRefused {
        code: ROUTING_POLICY_REFUSAL_CODE.to_string(),
        message: "active Management policy refused every candidate before payload dispatch".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_lifecycle::{
        ApplicationBindingV1, PolicyReferenceV1, PolicyRevisionV1, PolicyWorkspaceV1,
        POLICY_LIFECYCLE_VERSION,
    };
    use serde_json::json;

    fn repository(policy: Value) -> InMemoryPolicyRepository {
        let revision = PolicyRevisionV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.into(),
            policy_id: "policy:routing".into(),
            revision_id: "r1".into(),
            authority: "authority:test".into(),
            scope: "application:test".into(),
            disposition: PolicyDisposition::Stored,
            policy,
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        };
        let binding = ApplicationBindingV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.into(),
            binding_id: "binding:test".into(),
            application_id: "application:test".into(),
            authority: "authority:test".into(),
            policies: vec![PolicyReferenceV1 {
                policy_id: revision.policy_id.clone(),
                revision_id: revision.revision_id.clone(),
                authority_rank: 100,
                mandatory: true,
                order: 1,
            }],
            policy_sets: vec![],
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        };
        let mut repository =
            crate::policy_lifecycle::repository_from_workspace(PolicyWorkspaceV1 {
                revisions: vec![revision],
                policy_sets: vec![],
                binding,
                activation: None,
            })
            .unwrap();
        let activation = repository
            .activation_for_binding("binding:test", "authority:test", 100, Some(500))
            .unwrap();
        repository.activate(activation).unwrap();
        repository
    }

    fn candidate_evidence() -> RoutingCandidateEvidenceV1 {
        RoutingCandidateEvidenceV1 {
            schema_version: ROUTING_CANDIDATE_EVIDENCE_SCHEMA.into(),
            evidence_source: "iicp_client_discovery".into(),
            observed_at: 110,
            expires_at: 400,
            eligible_candidate_refs: vec![routing_candidate_ref("node-a").unwrap()],
            ineligible_count: 2,
            unresolved_count: 0,
        }
    }

    #[test]
    fn supported_constraints_project_and_tampering_fails() {
        let repository = repository(json!({"all":[
            {"in":["region",["EU","eu-central"]]},
            {"eq":["manifest_identity_level","known_operator"]},
            {"eq":["retention_mode","none"]}
        ]}));
        let projection = project_active_routing_policy(
            &repository,
            "binding:test",
            &candidate_evidence(),
            120,
            180,
        )
        .unwrap();
        assert_eq!(projection.policy_generation, 1);
        assert_eq!(
            projection.routing_policy.allowed_regions,
            vec!["eu", "eu-central"]
        );
        assert_eq!(projection.routing_policy.known_operator_only, Some(true));
        assert_eq!(
            projection.routing_policy.require_no_payload_retention,
            Some(true)
        );
        verify_routing_enforcement_projection(&repository, &projection, 150).unwrap();

        let mut tampered = projection;
        tampered.routing_policy.allowed_regions = vec!["us".into()];
        assert!(matches!(
            verify_routing_enforcement_projection(&repository, &tampered, 150),
            Err(RoutingEnforcementError::DigestMismatch)
        ));
    }

    #[test]
    fn inactive_expired_and_unsupported_policy_fail_closed() {
        assert!(matches!(
            project_active_routing_policy(
                &InMemoryPolicyRepository::default(),
                "binding:missing",
                &candidate_evidence(),
                120,
                180
            ),
            Err(RoutingEnforcementError::Inactive)
        ));
        let unsupported_repository = repository(json!({"eq":["approved",true]}));
        assert!(matches!(
            project_active_routing_policy(
                &unsupported_repository,
                "binding:test",
                &candidate_evidence(),
                120,
                180,
            ),
            Err(RoutingEnforcementError::UnsupportedPolicy)
        ));
        let repository = repository(json!({"eq":["region","eu"]}));
        let projection = project_active_routing_policy(
            &repository,
            "binding:test",
            &candidate_evidence(),
            120,
            180,
        )
        .unwrap();
        assert!(matches!(
            verify_routing_enforcement_projection(&repository, &projection, 180),
            Err(RoutingEnforcementError::Expired)
        ));
        assert!(matches!(
            project_active_routing_policy(
                &repository,
                "binding:test",
                &candidate_evidence(),
                120,
                421,
            ),
            Err(RoutingEnforcementError::InvalidValidity)
        ));

        let mut stale_evidence = candidate_evidence();
        stale_evidence.expires_at = 120;
        assert!(matches!(
            project_active_routing_policy(&repository, "binding:test", &stale_evidence, 120, 180,),
            Err(RoutingEnforcementError::CandidateEvidenceStale)
        ));
        let mut unresolved_evidence = candidate_evidence();
        unresolved_evidence.unresolved_count = 1;
        assert!(matches!(
            project_active_routing_policy(
                &repository,
                "binding:test",
                &unresolved_evidence,
                120,
                180,
            ),
            Err(RoutingEnforcementError::CandidateEvidenceUnresolved)
        ));
    }

    #[test]
    fn a_new_active_generation_invalidates_an_older_projection() {
        let mut repository = repository(json!({"eq":["region","eu"]}));
        let projection = project_active_routing_policy(
            &repository,
            "binding:test",
            &candidate_evidence(),
            120,
            180,
        )
        .unwrap();
        let activation = repository
            .activation_for_binding("binding:test", "authority:test", 160, Some(500))
            .unwrap();
        repository.activate(activation).unwrap();
        assert!(verify_routing_enforcement_projection(&repository, &projection, 170).is_err());
    }

    #[test]
    fn contradictory_regions_deny_all_instead_of_becoming_unrestricted() {
        let repository = repository(json!({"all":[
            {"in":["region",["eu"]]},
            {"in":["region",["us"]]}
        ]}));
        let projection = project_active_routing_policy(
            &repository,
            "binding:test",
            &candidate_evidence(),
            120,
            180,
        )
        .unwrap();
        assert!(projection.deny_all);
        assert!(projection.routing_policy.allowed_regions.is_empty());
    }

    #[test]
    fn request_policy_is_intersected_and_cannot_weaken_the_baseline() {
        let baseline = RoutingPolicy {
            profile: RoutingProfile::Standard,
            allowed_regions: vec!["eu".into()],
            require_encryption: Some(true),
            ..Default::default()
        };
        let request = RoutingPolicy {
            profile: RoutingProfile::DebugOverride,
            allowed_regions: vec!["us".into()],
            require_encryption: Some(false),
            ..Default::default()
        };
        let (combined, deny_all) = intersect_routing_policies(&baseline, &request);
        assert!(deny_all);
        assert_eq!(combined.require_encryption, Some(true));
    }
}
