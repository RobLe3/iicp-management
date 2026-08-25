use crate::policy_lifecycle::{InMemoryPolicyRepository, PolicyLifecycleError, PolicyRepository};
use crate::{digest, PolicyDecision};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;

pub const CANDIDATE_EVIDENCE_SCHEMA: &str = "iicp.management-candidate-evidence.v1";
pub const RESOLUTION_INSPECTION_SCHEMA: &str = "iicp.management-resolution-inspection.v1";
pub const MAX_CANDIDATES: usize = 10_000;
pub const MAX_FACT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateCompatibilityV1 {
    Compatible,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceV1 {
    pub candidate_id: String,
    pub compatibility: CandidateCompatibilityV1,
    pub facts: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceSnapshotV1 {
    pub schema_version: String,
    pub snapshot_id: String,
    pub evidence_source: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub authorizes_mutation: bool,
    pub candidates: Vec<CandidateEvidenceV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateEligibilityV1 {
    Eligible,
    Ineligible,
    Unresolved,
}

/// Classify one candidate after policy evaluation. This function performs no
/// ranking, selection, dispatch, or mutation.
pub fn candidate_eligibility(
    decision: &PolicyDecision,
    compatibility: &CandidateCompatibilityV1,
    evidence_expired: bool,
) -> (CandidateEligibilityV1, Option<&'static str>) {
    if evidence_expired {
        return (
            CandidateEligibilityV1::Unresolved,
            Some("IICP-MGMT-CANDIDATE-EVIDENCE-STALE"),
        );
    }
    match (decision, compatibility) {
        (PolicyDecision::Deny, _) => (CandidateEligibilityV1::Ineligible, None),
        (PolicyDecision::Indeterminate, _) => (CandidateEligibilityV1::Unresolved, None),
        (PolicyDecision::Allow, CandidateCompatibilityV1::Compatible) => {
            (CandidateEligibilityV1::Eligible, None)
        }
        (PolicyDecision::Allow, CandidateCompatibilityV1::Incompatible) => (
            CandidateEligibilityV1::Ineligible,
            Some("IICP-MGMT-CANDIDATE-INCOMPATIBLE"),
        ),
        (PolicyDecision::Allow, CandidateCompatibilityV1::Unknown) => (
            CandidateEligibilityV1::Unresolved,
            Some("IICP-MGMT-CANDIDATE-COMPATIBILITY-UNKNOWN"),
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateResolutionV1 {
    pub candidate_id: String,
    pub compatibility: CandidateCompatibilityV1,
    pub decision: PolicyDecision,
    pub eligibility: CandidateEligibilityV1,
    pub reason_codes: Vec<String>,
    pub determining_policy_ids: Vec<String>,
    pub fact_snapshot_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionInspectionV1 {
    pub schema_version: String,
    pub application_id: String,
    pub binding_id: String,
    pub intent: String,
    pub evidence_source: String,
    pub evidence_snapshot_digest: String,
    pub evidence_expired: bool,
    pub authorizes_mutation: bool,
    pub ranking_applied: bool,
    pub eligible: u64,
    pub ineligible: u64,
    pub unresolved: u64,
    pub entries: Vec<CandidateResolutionV1>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResolutionInspectionError {
    #[error("CANDIDATE_EVIDENCE_INVALID")]
    InvalidEvidence,
    #[error("CANDIDATE_EVIDENCE_DUPLICATE")]
    DuplicateCandidate,
    #[error("CANDIDATE_EVIDENCE_SECRET_REJECTED")]
    SecretRejected,
    #[error(transparent)]
    Policy(#[from] PolicyLifecycleError),
    #[error("RESOLUTION_DIGEST_FAILED")]
    DigestFailed,
}

pub fn inspect_resolution(
    repository: &InMemoryPolicyRepository,
    binding_id: &str,
    intent: &str,
    snapshot: &CandidateEvidenceSnapshotV1,
    now: u64,
) -> Result<ResolutionInspectionV1, ResolutionInspectionError> {
    validate_snapshot(snapshot, intent, binding_id, now)?;
    let evidence_expired = now > snapshot.expires_at;
    let evidence_snapshot_digest =
        digest(snapshot).map_err(|_| ResolutionInspectionError::DigestFailed)?;
    let mut entries = Vec::with_capacity(snapshot.candidates.len());
    for candidate in &snapshot.candidates {
        let effective = repository.effective_policy(binding_id, &candidate.facts)?;
        let mut reason_codes = effective.reason_codes.clone();
        let (eligibility, classification_reason) = candidate_eligibility(
            &effective.decision,
            &candidate.compatibility,
            evidence_expired,
        );
        if let Some(reason) = classification_reason {
            reason_codes.push(reason.into());
        }
        reason_codes.sort();
        reason_codes.dedup();
        let determining_policy_ids = effective
            .sources
            .iter()
            .filter(|source| {
                source.decision == effective.decision
                    || (effective.decision == PolicyDecision::Indeterminate && source.mandatory)
            })
            .map(|source| source.policy_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        entries.push(CandidateResolutionV1 {
            candidate_id: candidate.candidate_id.clone(),
            compatibility: candidate.compatibility.clone(),
            decision: effective.decision,
            eligibility,
            reason_codes,
            determining_policy_ids,
            fact_snapshot_digest: effective.fact_snapshot_digest,
        });
    }
    entries.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    let application_id = repository
        .binding(binding_id)
        .ok_or(PolicyLifecycleError::BindingNotFound)?
        .application_id
        .clone();
    Ok(ResolutionInspectionV1 {
        schema_version: RESOLUTION_INSPECTION_SCHEMA.into(),
        application_id,
        binding_id: binding_id.into(),
        intent: intent.into(),
        evidence_source: snapshot.evidence_source.clone(),
        evidence_snapshot_digest,
        evidence_expired,
        authorizes_mutation: false,
        ranking_applied: false,
        eligible: entries
            .iter()
            .filter(|entry| entry.eligibility == CandidateEligibilityV1::Eligible)
            .count() as u64,
        ineligible: entries
            .iter()
            .filter(|entry| entry.eligibility == CandidateEligibilityV1::Ineligible)
            .count() as u64,
        unresolved: entries
            .iter()
            .filter(|entry| entry.eligibility == CandidateEligibilityV1::Unresolved)
            .count() as u64,
        entries,
    })
}

fn validate_snapshot(
    snapshot: &CandidateEvidenceSnapshotV1,
    intent: &str,
    binding_id: &str,
    now: u64,
) -> Result<(), ResolutionInspectionError> {
    if snapshot.schema_version != CANDIDATE_EVIDENCE_SCHEMA
        || snapshot.snapshot_id.trim().is_empty()
        || snapshot.evidence_source.trim().is_empty()
        || intent.trim().is_empty()
        || binding_id.trim().is_empty()
        || snapshot.authorizes_mutation
        || snapshot.observed_at > now
        || snapshot.observed_at > snapshot.expires_at
        || snapshot.candidates.len() > MAX_CANDIDATES
    {
        return Err(ResolutionInspectionError::InvalidEvidence);
    }
    let mut identifiers = BTreeSet::new();
    for candidate in &snapshot.candidates {
        if candidate.candidate_id.trim().is_empty()
            || !candidate.facts.is_object()
            || serde_json::to_vec(&candidate.facts)
                .map_err(|_| ResolutionInspectionError::InvalidEvidence)?
                .len()
                > MAX_FACT_BYTES
        {
            return Err(ResolutionInspectionError::InvalidEvidence);
        }
        if !identifiers.insert(candidate.candidate_id.as_str()) {
            return Err(ResolutionInspectionError::DuplicateCandidate);
        }
        if contains_secret(&candidate.facts) {
            return Err(ResolutionInspectionError::SecretRejected);
        }
    }
    Ok(())
}

fn contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "secret"
                    | "secret_value"
                    | "operator_secret"
                    | "password"
                    | "token"
                    | "access_token"
                    | "refresh_token"
                    | "bearer_token"
                    | "api_key"
                    | "private_key"
                    | "prompt"
                    | "response"
                    | "task_payload"
            ) || contains_secret(value)
        }),
        Value::Array(items) => items.iter().any(contains_secret),
        _ => false,
    }
}
