use crate::{
    adapters::{validate_adapter_inspection, AdapterInspectionV1},
    digest,
    rollout::{ConvergenceStatusV1, OperationRunV1},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DRIFT_SCHEMA: &str = "iicp.management-drift-assessment.v1";
pub const RECONCILIATION_SCHEMA: &str = "iicp.management-reconciliation-proposal.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriftState {
    InSync,
    Drifted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    Unclassified,
    SafeMetadata,
    CapabilityRuntime,
    Membership,
    TrustIdentity,
    SecretReference,
    IrreversibleDivergence,
}
impl DriftClass {
    pub fn permits_bounded_reconciliation(&self) -> bool {
        matches!(self, Self::SafeMetadata | Self::CapabilityRuntime)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriftAssessmentV1 {
    pub schema_version: String,
    pub assessment_id: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub target_id: String,
    pub expected_digest: String,
    pub expected_generation: u64,
    pub observed_digest: Option<String>,
    pub observed_generation: Option<u64>,
    pub state: DriftState,
    pub drift_class: DriftClass,
    pub evidence_source: String,
    pub observed_at: u64,
    pub expires_at: u64,
    pub reason: String,
    pub authorizes_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriftStatusV1 {
    pub schema_version: String,
    pub run_id: String,
    pub manifest_digest: String,
    pub authorizes_mutation: bool,
    pub assessments: Vec<DriftAssessmentV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationProposalV1 {
    pub schema_version: String,
    pub proposal_id: String,
    pub run_id: String,
    pub target_id: String,
    pub assessment_digest: String,
    pub drift_class: DriftClass,
    pub desired_digest: String,
    pub expected_observed_generation: u64,
    pub related_operation_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub requires_fresh_apply_gate: bool,
    pub authorizes_mutation: bool,
}

pub fn assess_inspection(
    manifest: &OperationRunV1,
    status: &ConvergenceStatusV1,
    inspection: &AdapterInspectionV1,
    now: u64,
) -> Result<Vec<DriftAssessmentV1>, String> {
    validate_adapter_inspection(inspection, &BTreeSet::new(), now, 60)
        .map_err(|_| "DRIFT_EVIDENCE_INVALID")?;
    if status.run_id != manifest.run_id
        || status.manifest_digest != digest(manifest).map_err(|_| "DRIFT_BINDING_INVALID")?
    {
        return Err("DRIFT_BINDING_INVALID".into());
    }
    let mut assessments = Vec::with_capacity(manifest.targets.len());
    for target in &manifest.targets {
        let target_status = status
            .targets
            .iter()
            .find(|value| value.target_id == target.target_id)
            .ok_or("DRIFT_TARGET_NOT_FOUND")?;
        let expected_receipt = target_status.receipt.as_ref().and_then(|receipt| {
            receipt
                .verification_receipt
                .as_ref()
                .or(receipt.adapter_receipt.as_ref())
        });
        let evidence = inspection.entries.iter().find(|entry| {
            entry.target_id == target.target_id
                && entry.registered_capability == target.gate.operation.capability
        });
        let has_verified_expectation = expected_receipt.is_some();
        let (expected_digest, expected_generation) = expected_receipt
            .map(|receipt| (receipt.result_digest.clone(), receipt.generation))
            .unwrap_or_else(|| {
                (
                    target.gate.operation.desired_digest.clone(),
                    target.gate.operation.expected_generation,
                )
            });
        let (observed_digest, observed_generation, state, reason) = match evidence {
            _ if !has_verified_expectation => (
                None,
                None,
                DriftState::Unknown,
                "DRIFT_EXPECTED_RECEIPT_MISSING",
            ),
            None => (None, None, DriftState::Unknown, "DRIFT_EVIDENCE_MISSING"),
            Some(entry)
                if entry.observation_digest.is_none() || entry.observed_generation.is_none() =>
            {
                (
                    entry.observation_digest.clone(),
                    entry.observed_generation,
                    DriftState::Unknown,
                    "DRIFT_EVIDENCE_INCOMPLETE",
                )
            }
            Some(entry)
                if entry.observation_digest.as_ref() == Some(&expected_digest)
                    && entry.observed_generation == Some(expected_generation) =>
            {
                (
                    entry.observation_digest.clone(),
                    entry.observed_generation,
                    DriftState::InSync,
                    "DRIFT_IN_SYNC",
                )
            }
            Some(entry) => (
                entry.observation_digest.clone(),
                entry.observed_generation,
                DriftState::Drifted,
                "DRIFT_DETECTED",
            ),
        };
        assessments.push(DriftAssessmentV1 {
            schema_version: DRIFT_SCHEMA.into(),
            assessment_id: format!(
                "{}:{}:{}",
                manifest.run_id, target.target_id, inspection.observed_at
            ),
            run_id: manifest.run_id.clone(),
            manifest_digest: status.manifest_digest.clone(),
            target_id: target.target_id.clone(),
            expected_digest,
            expected_generation,
            observed_digest,
            observed_generation,
            state,
            drift_class: DriftClass::Unclassified,
            evidence_source: inspection.evidence_source.clone(),
            observed_at: inspection.observed_at,
            expires_at: inspection.expires_at,
            reason: reason.into(),
            authorizes_mutation: false,
        });
    }
    Ok(assessments)
}

pub fn validate_proposal(
    value: &ReconciliationProposalV1,
    assessment: &DriftAssessmentV1,
    now: u64,
) -> Result<(), String> {
    if value.schema_version != RECONCILIATION_SCHEMA
        || value.authorizes_mutation
        || !value.requires_fresh_apply_gate
        || value.run_id != assessment.run_id
        || value.target_id != assessment.target_id
        || value.assessment_digest != digest(assessment).map_err(|_| "RECONCILIATION_INVALID")?
        || assessment.state != DriftState::Drifted
        || now > assessment.expires_at
        || !value.drift_class.permits_bounded_reconciliation()
        || value.expected_observed_generation
            != assessment
                .observed_generation
                .ok_or("RECONCILIATION_EVIDENCE_INCOMPLETE")?
        || value.created_at > now
        || value.created_at >= value.expires_at
        || now > value.expires_at
    {
        return Err("RECONCILIATION_INVALID".into());
    }
    Ok(())
}
