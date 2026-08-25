use crate::{digest, evaluate_policy, ExtensionRequirement, ManagedResource, PolicyDecision};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const POLICY_LIFECYCLE_VERSION: &str = "1";
pub const POLICY_REVISION_KIND: &str = "iicp.management/policy-revision-v1";
pub const POLICY_SET_KIND: &str = "iicp.management/policy-set-v1";
pub const APPLICATION_BINDING_KIND: &str = "iicp.management/application-binding-v1";
pub const POLICY_ACTIVATION_KIND: &str = "iicp.management/policy-activation-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyWorkspaceV1 {
    #[serde(default)]
    pub revisions: Vec<PolicyRevisionV1>,
    #[serde(default)]
    pub policy_sets: Vec<PolicySetV1>,
    pub binding: ApplicationBindingV1,
    #[serde(default)]
    pub activation: Option<PolicyActivationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    Stored,
    Invalid,
    Active,
    Superseded,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevisionV1 {
    pub schema_version: String,
    pub policy_id: String,
    pub revision_id: String,
    pub authority: String,
    pub scope: String,
    pub disposition: PolicyDisposition,
    pub policy: Value,
    #[serde(default)]
    pub valid_from: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<u64>,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySetMemberV1 {
    pub policy_id: String,
    pub revision_id: String,
    pub authority_rank: u32,
    pub mandatory: bool,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySetV1 {
    pub schema_version: String,
    pub policy_set_id: String,
    pub revision_id: String,
    pub authority: String,
    pub members: Vec<PolicySetMemberV1>,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyReferenceV1 {
    pub policy_id: String,
    pub revision_id: String,
    pub authority_rank: u32,
    pub mandatory: bool,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySetReferenceV1 {
    pub policy_set_id: String,
    pub revision_id: String,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationBindingV1 {
    pub schema_version: String,
    pub binding_id: String,
    pub application_id: String,
    pub authority: String,
    #[serde(default)]
    pub policies: Vec<PolicyReferenceV1>,
    #[serde(default)]
    pub policy_sets: Vec<PolicySetReferenceV1>,
    #[serde(default)]
    pub valid_from: Option<u64>,
    #[serde(default)]
    pub valid_until: Option<u64>,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyActivationV1 {
    pub schema_version: String,
    pub activation_id: String,
    pub binding_id: String,
    pub authority: String,
    pub expected_generation: u64,
    pub target_generation: u64,
    pub binding_digest: String,
    pub policy_revision_digests: BTreeMap<String, String>,
    pub activated_at: u64,
    #[serde(default)]
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySourceDecisionV1 {
    pub policy_id: String,
    pub revision_id: String,
    pub authority_rank: u32,
    pub mandatory: bool,
    pub decision: PolicyDecision,
    pub reason_codes: Vec<String>,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicyViewV1 {
    pub schema_version: String,
    pub application_id: String,
    pub binding_id: String,
    pub binding_digest: String,
    pub fact_snapshot_digest: String,
    pub decision: PolicyDecision,
    pub reason_codes: Vec<String>,
    pub sources: Vec<PolicySourceDecisionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyInventoryEntryV1 {
    pub policy_id: String,
    pub revision_id: String,
    pub disposition: PolicyDisposition,
    pub policy_digest: String,
    pub active_binding_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyInventoryV1 {
    pub schema_version: String,
    pub entries: Vec<PolicyInventoryEntryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApplicationPolicyBriefV1 {
    pub schema_version: String,
    pub application_id: String,
    pub binding_id: String,
    pub active_generation: Option<u64>,
    pub effective_policy: EffectivePolicyViewV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimulationResultV1 {
    pub schema_version: String,
    pub current: EffectivePolicyViewV1,
    pub proposed: EffectivePolicyViewV1,
    pub decision_changed: bool,
    pub newly_allowed: bool,
    pub newly_denied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolutionSummaryV1 {
    pub schema_version: String,
    pub application_id: String,
    pub intent: String,
    pub eligible: bool,
    pub decision: PolicyDecision,
    pub effective_policy_digest: String,
    pub evidence_snapshot_digest: String,
    pub preferences: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionExplanationV1 {
    pub schema_version: String,
    pub decision_id: String,
    pub application_id: String,
    pub intent: String,
    pub decision: PolicyDecision,
    pub reason_codes: Vec<String>,
    pub determining_policy_ids: Vec<String>,
    pub fact_snapshot_digest: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyLifecycleError {
    #[error("POLICY_UNSUPPORTED_VERSION")]
    UnsupportedVersion,
    #[error("POLICY_EMPTY_IDENTIFIER")]
    EmptyIdentifier,
    #[error("POLICY_INVALID_VALIDITY")]
    InvalidValidity,
    #[error("POLICY_DUPLICATE_MEMBER")]
    DuplicateMember,
    #[error("POLICY_REVISION_NOT_FOUND")]
    RevisionNotFound,
    #[error("POLICY_SET_NOT_FOUND")]
    SetNotFound,
    #[error("POLICY_BINDING_NOT_FOUND")]
    BindingNotFound,
    #[error("POLICY_DIGEST_MISMATCH")]
    DigestMismatch,
    #[error("POLICY_STALE_GENERATION")]
    StaleGeneration,
    #[error("POLICY_ACTIVATION_INVALID")]
    InvalidActivation,
    #[error("POLICY_EVALUATION_FAILED")]
    EvaluationFailed,
    #[error("POLICY_UNSUPPORTED_REQUIRED_EXTENSION:{0}")]
    UnsupportedRequiredExtension(String),
}

fn valid_window(from: Option<u64>, until: Option<u64>) -> bool {
    !matches!((from, until), (Some(start), Some(end)) if end <= start)
}

fn window_contains(from: Option<u64>, until: Option<u64>, at: u64) -> bool {
    from.is_none_or(|start| at >= start) && until.is_none_or(|end| at < end)
}

fn validate_activatable(
    revision: &PolicyRevisionV1,
    at: Option<u64>,
) -> Result<(), PolicyLifecycleError> {
    if matches!(
        revision.disposition,
        PolicyDisposition::Invalid | PolicyDisposition::Archived
    ) || at
        .is_some_and(|instant| !window_contains(revision.valid_from, revision.valid_until, instant))
    {
        return Err(PolicyLifecycleError::InvalidActivation);
    }
    Ok(())
}

fn identifiers(values: &[&str]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
}

fn validate_extensions(
    extensions: &[ExtensionRequirement],
    supported: &BTreeSet<String>,
) -> Result<(), PolicyLifecycleError> {
    for extension in extensions {
        if !supported.contains(&extension.id)
            && matches!(
                extension.class,
                crate::ExtensionClass::RequiredUnderstood
                    | crate::ExtensionClass::RequiredSecurityCritical
            )
        {
            return Err(PolicyLifecycleError::UnsupportedRequiredExtension(
                extension.id.clone(),
            ));
        }
    }
    Ok(())
}

pub fn validate_policy_revision(value: &PolicyRevisionV1) -> Result<(), PolicyLifecycleError> {
    if value.schema_version != POLICY_LIFECYCLE_VERSION {
        return Err(PolicyLifecycleError::UnsupportedVersion);
    }
    if !identifiers(&[
        &value.policy_id,
        &value.revision_id,
        &value.authority,
        &value.scope,
    ]) {
        return Err(PolicyLifecycleError::EmptyIdentifier);
    }
    if !valid_window(value.valid_from, value.valid_until) {
        return Err(PolicyLifecycleError::InvalidValidity);
    }
    Ok(())
}

pub fn validate_policy_set(value: &PolicySetV1) -> Result<(), PolicyLifecycleError> {
    if value.schema_version != POLICY_LIFECYCLE_VERSION {
        return Err(PolicyLifecycleError::UnsupportedVersion);
    }
    if !identifiers(&[&value.policy_set_id, &value.revision_id, &value.authority]) {
        return Err(PolicyLifecycleError::EmptyIdentifier);
    }
    let mut identities = BTreeSet::new();
    let mut orders = BTreeSet::new();
    for member in &value.members {
        if !identifiers(&[&member.policy_id, &member.revision_id]) {
            return Err(PolicyLifecycleError::EmptyIdentifier);
        }
        if !identities.insert((&member.policy_id, &member.revision_id))
            || !orders.insert(member.order)
        {
            return Err(PolicyLifecycleError::DuplicateMember);
        }
    }
    Ok(())
}

pub fn validate_application_binding(
    value: &ApplicationBindingV1,
) -> Result<(), PolicyLifecycleError> {
    if value.schema_version != POLICY_LIFECYCLE_VERSION {
        return Err(PolicyLifecycleError::UnsupportedVersion);
    }
    if !identifiers(&[&value.binding_id, &value.application_id, &value.authority]) {
        return Err(PolicyLifecycleError::EmptyIdentifier);
    }
    if !valid_window(value.valid_from, value.valid_until) {
        return Err(PolicyLifecycleError::InvalidValidity);
    }
    let mut orders = BTreeSet::new();
    for reference in &value.policies {
        if !identifiers(&[&reference.policy_id, &reference.revision_id])
            || !orders.insert(reference.order)
        {
            return Err(PolicyLifecycleError::DuplicateMember);
        }
    }
    for reference in &value.policy_sets {
        if !identifiers(&[&reference.policy_set_id, &reference.revision_id])
            || !orders.insert(reference.order)
        {
            return Err(PolicyLifecycleError::DuplicateMember);
        }
    }
    Ok(())
}

pub trait PolicyRepository {
    fn store_revision(
        &mut self,
        revision: PolicyRevisionV1,
    ) -> Result<String, PolicyLifecycleError>;
    fn store_set(&mut self, set: PolicySetV1) -> Result<String, PolicyLifecycleError>;
    fn store_binding(
        &mut self,
        binding: ApplicationBindingV1,
    ) -> Result<String, PolicyLifecycleError>;
    fn activate(&mut self, activation: PolicyActivationV1) -> Result<(), PolicyLifecycleError>;
    fn revision(&self, policy_id: &str, revision_id: &str) -> Option<&PolicyRevisionV1>;
    fn binding(&self, binding_id: &str) -> Option<&ApplicationBindingV1>;
    fn active(&self, binding_id: &str) -> Option<&PolicyActivationV1>;
}

#[derive(Debug, Default)]
pub struct InMemoryPolicyRepository {
    revisions: BTreeMap<(String, String), PolicyRevisionV1>,
    sets: BTreeMap<(String, String), PolicySetV1>,
    bindings: BTreeMap<String, ApplicationBindingV1>,
    activations: BTreeMap<String, PolicyActivationV1>,
    generation: u64,
    supported_extensions: BTreeSet<String>,
}

impl PolicyRepository for InMemoryPolicyRepository {
    fn store_revision(
        &mut self,
        revision: PolicyRevisionV1,
    ) -> Result<String, PolicyLifecycleError> {
        validate_policy_revision(&revision)?;
        validate_extensions(&revision.extensions, &self.supported_extensions)?;
        let revision_digest =
            digest(&revision).map_err(|_| PolicyLifecycleError::DigestMismatch)?;
        let key = (revision.policy_id.clone(), revision.revision_id.clone());
        if let Some(existing) = self.revisions.get(&key) {
            if digest(existing).map_err(|_| PolicyLifecycleError::DigestMismatch)?
                != revision_digest
            {
                return Err(PolicyLifecycleError::DigestMismatch);
            }
            return Ok(revision_digest);
        }
        self.revisions.insert(key, revision);
        Ok(revision_digest)
    }

    fn store_set(&mut self, set: PolicySetV1) -> Result<String, PolicyLifecycleError> {
        validate_policy_set(&set)?;
        validate_extensions(&set.extensions, &self.supported_extensions)?;
        for member in &set.members {
            if !self
                .revisions
                .contains_key(&(member.policy_id.clone(), member.revision_id.clone()))
            {
                return Err(PolicyLifecycleError::RevisionNotFound);
            }
        }
        let set_digest = digest(&set).map_err(|_| PolicyLifecycleError::DigestMismatch)?;
        let key = (set.policy_set_id.clone(), set.revision_id.clone());
        if let Some(existing) = self.sets.get(&key) {
            if digest(existing).map_err(|_| PolicyLifecycleError::DigestMismatch)? != set_digest {
                return Err(PolicyLifecycleError::DigestMismatch);
            }
            return Ok(set_digest);
        }
        self.sets.insert(key, set);
        Ok(set_digest)
    }

    fn store_binding(
        &mut self,
        binding: ApplicationBindingV1,
    ) -> Result<String, PolicyLifecycleError> {
        validate_application_binding(&binding)?;
        validate_extensions(&binding.extensions, &self.supported_extensions)?;
        for reference in &binding.policies {
            if !self
                .revisions
                .contains_key(&(reference.policy_id.clone(), reference.revision_id.clone()))
            {
                return Err(PolicyLifecycleError::RevisionNotFound);
            }
        }
        for reference in &binding.policy_sets {
            if !self.sets.contains_key(&(
                reference.policy_set_id.clone(),
                reference.revision_id.clone(),
            )) {
                return Err(PolicyLifecycleError::SetNotFound);
            }
        }
        let binding_digest = digest(&binding).map_err(|_| PolicyLifecycleError::DigestMismatch)?;
        if let Some(existing) = self.bindings.get(&binding.binding_id) {
            if digest(existing).map_err(|_| PolicyLifecycleError::DigestMismatch)? != binding_digest
            {
                return Err(PolicyLifecycleError::DigestMismatch);
            }
            return Ok(binding_digest);
        }
        self.bindings.insert(binding.binding_id.clone(), binding);
        Ok(binding_digest)
    }

    fn activate(&mut self, activation: PolicyActivationV1) -> Result<(), PolicyLifecycleError> {
        if activation.schema_version != POLICY_LIFECYCLE_VERSION
            || !identifiers(&[
                &activation.activation_id,
                &activation.binding_id,
                &activation.authority,
            ])
            || activation.expected_generation != self.generation
            || activation.target_generation != self.generation + 1
            || activation
                .valid_until
                .is_some_and(|until| until <= activation.activated_at)
        {
            return Err(if activation.expected_generation != self.generation {
                PolicyLifecycleError::StaleGeneration
            } else {
                PolicyLifecycleError::InvalidActivation
            });
        }
        let binding = self
            .bindings
            .get(&activation.binding_id)
            .ok_or(PolicyLifecycleError::BindingNotFound)?;
        if digest(binding).map_err(|_| PolicyLifecycleError::DigestMismatch)?
            != activation.binding_digest
        {
            return Err(PolicyLifecycleError::DigestMismatch);
        }
        if !window_contains(
            binding.valid_from,
            binding.valid_until,
            activation.activated_at,
        ) {
            return Err(PolicyLifecycleError::InvalidActivation);
        }
        let expected = self.policy_digests_for_binding(binding, Some(activation.activated_at))?;
        if expected != activation.policy_revision_digests {
            return Err(PolicyLifecycleError::DigestMismatch);
        }
        self.generation = activation.target_generation;
        self.activations
            .insert(activation.binding_id.clone(), activation);
        Ok(())
    }

    fn revision(&self, policy_id: &str, revision_id: &str) -> Option<&PolicyRevisionV1> {
        self.revisions
            .get(&(policy_id.to_owned(), revision_id.to_owned()))
    }

    fn binding(&self, binding_id: &str) -> Option<&ApplicationBindingV1> {
        self.bindings.get(binding_id)
    }

    fn active(&self, binding_id: &str) -> Option<&PolicyActivationV1> {
        self.activations.get(binding_id)
    }
}

impl InMemoryPolicyRepository {
    pub fn with_supported_extensions(supported_extensions: BTreeSet<String>) -> Self {
        Self {
            supported_extensions,
            ..Self::default()
        }
    }

    fn policy_digests_for_binding(
        &self,
        binding: &ApplicationBindingV1,
        at: Option<u64>,
    ) -> Result<BTreeMap<String, String>, PolicyLifecycleError> {
        let mut result = BTreeMap::new();
        for reference in &binding.policies {
            let revision = self
                .revision(&reference.policy_id, &reference.revision_id)
                .ok_or(PolicyLifecycleError::RevisionNotFound)?;
            validate_activatable(revision, at)?;
            result.insert(
                format!("{}@{}", reference.policy_id, reference.revision_id),
                digest(revision).map_err(|_| PolicyLifecycleError::DigestMismatch)?,
            );
        }
        for set_ref in &binding.policy_sets {
            let set = self
                .sets
                .get(&(set_ref.policy_set_id.clone(), set_ref.revision_id.clone()))
                .ok_or(PolicyLifecycleError::SetNotFound)?;
            for member in &set.members {
                let revision = self
                    .revision(&member.policy_id, &member.revision_id)
                    .ok_or(PolicyLifecycleError::RevisionNotFound)?;
                validate_activatable(revision, at)?;
                result.insert(
                    format!("{}@{}", member.policy_id, member.revision_id),
                    digest(revision).map_err(|_| PolicyLifecycleError::DigestMismatch)?,
                );
            }
        }
        Ok(result)
    }

    pub fn activation_for_binding(
        &self,
        binding_id: &str,
        authority: &str,
        now: u64,
        valid_until: Option<u64>,
    ) -> Result<PolicyActivationV1, PolicyLifecycleError> {
        let binding = self
            .binding(binding_id)
            .ok_or(PolicyLifecycleError::BindingNotFound)?;
        Ok(PolicyActivationV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            activation_id: format!("activation-{}", self.generation + 1),
            binding_id: binding_id.to_string(),
            authority: authority.to_string(),
            expected_generation: self.generation,
            target_generation: self.generation + 1,
            binding_digest: digest(binding).map_err(|_| PolicyLifecycleError::DigestMismatch)?,
            policy_revision_digests: self.policy_digests_for_binding(binding, Some(now))?,
            activated_at: now,
            valid_until,
        })
    }

    fn sources_for_binding(
        &self,
        binding: &ApplicationBindingV1,
    ) -> Result<Vec<(PolicyReferenceV1, &PolicyRevisionV1)>, PolicyLifecycleError> {
        let mut sources = Vec::new();
        for reference in &binding.policies {
            sources.push((
                reference.clone(),
                self.revision(&reference.policy_id, &reference.revision_id)
                    .ok_or(PolicyLifecycleError::RevisionNotFound)?,
            ));
        }
        for set_reference in &binding.policy_sets {
            let set = self
                .sets
                .get(&(
                    set_reference.policy_set_id.clone(),
                    set_reference.revision_id.clone(),
                ))
                .ok_or(PolicyLifecycleError::SetNotFound)?;
            for member in &set.members {
                sources.push((
                    PolicyReferenceV1 {
                        policy_id: member.policy_id.clone(),
                        revision_id: member.revision_id.clone(),
                        authority_rank: member.authority_rank,
                        mandatory: member.mandatory,
                        order: set_reference.order.saturating_mul(10_000) + member.order,
                    },
                    self.revision(&member.policy_id, &member.revision_id)
                        .ok_or(PolicyLifecycleError::RevisionNotFound)?,
                ));
            }
        }
        sources.sort_by(|(a, _), (b, _)| {
            b.authority_rank
                .cmp(&a.authority_rank)
                .then(a.order.cmp(&b.order))
                .then(a.policy_id.cmp(&b.policy_id))
                .then(a.revision_id.cmp(&b.revision_id))
        });
        Ok(sources)
    }

    pub fn effective_policy(
        &self,
        binding_id: &str,
        facts: &Value,
    ) -> Result<EffectivePolicyViewV1, PolicyLifecycleError> {
        let binding = self
            .binding(binding_id)
            .ok_or(PolicyLifecycleError::BindingNotFound)?;
        let mut sources = Vec::new();
        for (reference, revision) in self.sources_for_binding(binding)? {
            let result = evaluate_policy(facts, &revision.policy)
                .map_err(|_| PolicyLifecycleError::EvaluationFailed)?;
            sources.push(PolicySourceDecisionV1 {
                policy_id: revision.policy_id.clone(),
                revision_id: revision.revision_id.clone(),
                authority_rank: reference.authority_rank,
                mandatory: reference.mandatory,
                decision: result.decision,
                reason_codes: result.reason_codes,
                policy_digest: result.policy_digest,
            });
        }
        let decision = if sources
            .iter()
            .any(|source| source.decision == PolicyDecision::Deny)
        {
            PolicyDecision::Deny
        } else if sources
            .iter()
            .any(|source| source.mandatory && source.decision == PolicyDecision::Indeterminate)
        {
            PolicyDecision::Indeterminate
        } else if !sources.is_empty()
            && sources
                .iter()
                .all(|source| source.decision == PolicyDecision::Allow)
        {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Indeterminate
        };
        let mut reason_codes = sources
            .iter()
            .flat_map(|source| source.reason_codes.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        reason_codes.insert(
            0,
            match decision {
                PolicyDecision::Allow => "IICP-POLICY-EFFECTIVE-ALLOW",
                PolicyDecision::Deny => "IICP-POLICY-EFFECTIVE-DENY",
                PolicyDecision::Indeterminate => "IICP-POLICY-EFFECTIVE-INDETERMINATE",
            }
            .to_string(),
        );
        Ok(EffectivePolicyViewV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            application_id: binding.application_id.clone(),
            binding_id: binding.binding_id.clone(),
            binding_digest: digest(binding).map_err(|_| PolicyLifecycleError::DigestMismatch)?,
            fact_snapshot_digest: digest(facts)
                .map_err(|_| PolicyLifecycleError::DigestMismatch)?,
            decision,
            reason_codes,
            sources,
        })
    }

    pub fn policy_inventory(
        &self,
        active_only: bool,
    ) -> Result<PolicyInventoryV1, PolicyLifecycleError> {
        let mut counts = BTreeMap::<String, u64>::new();
        for activation in self.activations.values() {
            for identity in activation.policy_revision_digests.keys() {
                *counts.entry(identity.clone()).or_default() += 1;
            }
        }
        let mut entries = Vec::new();
        for ((policy_id, revision_id), revision) in &self.revisions {
            let identity = format!("{policy_id}@{revision_id}");
            let active_binding_count = *counts.get(&identity).unwrap_or(&0);
            if active_only && active_binding_count == 0 {
                continue;
            }
            entries.push(PolicyInventoryEntryV1 {
                policy_id: policy_id.clone(),
                revision_id: revision_id.clone(),
                disposition: if active_binding_count > 0 {
                    PolicyDisposition::Active
                } else {
                    revision.disposition.clone()
                },
                policy_digest: digest(revision)
                    .map_err(|_| PolicyLifecycleError::DigestMismatch)?,
                active_binding_count,
            });
        }
        Ok(PolicyInventoryV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            entries,
        })
    }

    pub fn application_policy_brief(
        &self,
        binding_id: &str,
        facts: &Value,
    ) -> Result<ApplicationPolicyBriefV1, PolicyLifecycleError> {
        let effective_policy = self.effective_policy(binding_id, facts)?;
        Ok(ApplicationPolicyBriefV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            application_id: effective_policy.application_id.clone(),
            binding_id: binding_id.to_string(),
            active_generation: self.active(binding_id).map(|value| value.target_generation),
            effective_policy,
        })
    }

    pub fn resolution_summary(
        &self,
        binding_id: &str,
        intent: &str,
        facts: &Value,
        preferences: Vec<String>,
    ) -> Result<ResolutionSummaryV1, PolicyLifecycleError> {
        if intent.trim().is_empty() {
            return Err(PolicyLifecycleError::EmptyIdentifier);
        }
        let effective = self.effective_policy(binding_id, facts)?;
        let effective_policy_digest =
            digest(&effective).map_err(|_| PolicyLifecycleError::DigestMismatch)?;
        Ok(ResolutionSummaryV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            application_id: effective.application_id.clone(),
            intent: intent.to_string(),
            eligible: effective.decision == PolicyDecision::Allow,
            decision: effective.decision,
            effective_policy_digest,
            evidence_snapshot_digest: effective.fact_snapshot_digest,
            preferences,
        })
    }

    pub fn explain_decision(
        &self,
        decision_id: &str,
        intent: &str,
        effective: &EffectivePolicyViewV1,
    ) -> Result<DecisionExplanationV1, PolicyLifecycleError> {
        if !identifiers(&[decision_id, intent]) {
            return Err(PolicyLifecycleError::EmptyIdentifier);
        }
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
        Ok(DecisionExplanationV1 {
            schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
            decision_id: decision_id.to_string(),
            application_id: effective.application_id.clone(),
            intent: intent.to_string(),
            decision: effective.decision.clone(),
            reason_codes: effective.reason_codes.clone(),
            determining_policy_ids,
            fact_snapshot_digest: effective.fact_snapshot_digest.clone(),
        })
    }
}

pub fn repository_from_workspace(
    input: PolicyWorkspaceV1,
) -> Result<InMemoryPolicyRepository, PolicyLifecycleError> {
    let mut repository = InMemoryPolicyRepository::default();
    for revision in input.revisions {
        repository.store_revision(revision)?;
    }
    for set in input.policy_sets {
        repository.store_set(set)?;
    }
    repository.store_binding(input.binding)?;
    if let Some(activation) = input.activation {
        repository.activate(activation)?;
    }
    Ok(repository)
}

pub fn simulate_policy_change(
    current: EffectivePolicyViewV1,
    proposed: EffectivePolicyViewV1,
) -> SimulationResultV1 {
    let decision_changed = current.decision != proposed.decision;
    let newly_allowed =
        current.decision != PolicyDecision::Allow && proposed.decision == PolicyDecision::Allow;
    let newly_denied =
        current.decision != PolicyDecision::Deny && proposed.decision == PolicyDecision::Deny;
    SimulationResultV1 {
        schema_version: POLICY_LIFECYCLE_VERSION.to_string(),
        current,
        proposed,
        decision_changed,
        newly_allowed,
        newly_denied,
    }
}

pub fn lifecycle_resource<T: Serialize>(
    resource_id: &str,
    kind: &str,
    value: &T,
) -> Result<ManagedResource, PolicyLifecycleError> {
    if !identifiers(&[resource_id, kind]) {
        return Err(PolicyLifecycleError::EmptyIdentifier);
    }
    Ok(ManagedResource {
        resource_id: resource_id.to_string(),
        kind: kind.to_string(),
        desired: serde_json::to_value(value).map_err(|_| PolicyLifecycleError::DigestMismatch)?,
        secret_refs: BTreeMap::new(),
    })
}
