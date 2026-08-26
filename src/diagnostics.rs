use crate::adapters::{validate_adapter_inspection, AdapterInspectionV1};
use crate::bootstrap::{
    doctor, validate_assessment, BootstrapAssessmentV1, CheckState, DoctorCheckV1,
};
use crate::controller::ControllerSnapshot;
use crate::digest;
use crate::profile::{
    intersect_profile, profile_digest, validate_profile, ManagementProfileRequirementV1,
    ManagementProfileV1, ProfileCompatibility,
};
use crate::rollout::{ConvergenceStatusV1, RunState, TargetRunState, ROLLOUT_SCHEMA};
use crate::runtime_observation::{
    enum_string, validate_runtime_observation, RuntimeEffectiveStateV1, RuntimeEvidenceStateV1,
    RuntimeObservationV1,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DIAGNOSTIC_SCHEMA: &str = "iicp.management-diagnostic-bundle.v1";
pub const DIAGNOSTIC_SCHEMA_V2: &str = "iicp.management-diagnostic-bundle.v2";
pub const DIAGNOSTIC_EVIDENCE_CLASS: &str = "operator_diagnostic";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticArtifactState {
    Valid,
    NotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticArtifactV1 {
    pub kind: String,
    pub state: DiagnosticArtifactState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticControllerV1 {
    pub generation: u64,
    pub decision_counts: BTreeMap<String, u64>,
    pub target_state: String,
    pub observed_state: String,
    pub effective_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticAdapterV1 {
    pub target_count: u64,
    pub converged: u64,
    pub partial: u64,
    pub failed: u64,
    pub unknown: u64,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticProfileV1 {
    pub profile_digest: String,
    pub compatibility: ProfileCompatibility,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRolloutV1 {
    pub state: RunState,
    pub current_batch: u32,
    pub target_counts: BTreeMap<String, u64>,
    pub partial_accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBundleV1 {
    pub schema_version: String,
    pub bundle_id: String,
    pub evidence_class: String,
    pub tool_version: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub authorizes_mutation: bool,
    pub overall: CheckState,
    pub artifacts: Vec<DiagnosticArtifactV1>,
    pub checks: Vec<DoctorCheckV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<DiagnosticControllerV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<DiagnosticAdapterV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<DiagnosticProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout: Option<DiagnosticRolloutV1>,
    pub safe_next_actions: Vec<String>,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRuntimeV1 {
    pub evidence_state: RuntimeEvidenceStateV1,
    pub reported_liveness: String,
    pub reported_readiness: String,
    pub effective_state: RuntimeEffectiveStateV1,
    pub reason_codes: Vec<String>,
    pub subsystem_state_counts: BTreeMap<String, u64>,
    pub external_connectivity_state_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticBundleV2 {
    #[serde(flatten)]
    pub base: DiagnosticBundleV1,
    pub runtime: DiagnosticRuntimeV1,
}

fn artifact<T: Serialize>(
    kind: &str,
    value: Option<&T>,
    observed_at: Option<u64>,
    expires_at: Option<u64>,
) -> Result<DiagnosticArtifactV1, String> {
    Ok(match value {
        Some(value) => DiagnosticArtifactV1 {
            kind: kind.into(),
            state: DiagnosticArtifactState::Valid,
            source_digest: Some(digest(value).map_err(|_| "DIAGNOSTIC_DIGEST_FAILED")?),
            observed_at,
            expires_at,
        },
        None => DiagnosticArtifactV1 {
            kind: kind.into(),
            state: DiagnosticArtifactState::NotAvailable,
            source_digest: None,
            observed_at: None,
            expires_at: None,
        },
    })
}

fn controller_summary(value: &ControllerSnapshot) -> DiagnosticControllerV1 {
    let mut decision_counts = BTreeMap::new();
    for decision in &value.recent_decisions {
        *decision_counts
            .entry(format!("{:?}", decision.decision).to_ascii_lowercase())
            .or_insert(0) += 1;
    }
    DiagnosticControllerV1 {
        generation: value.generation,
        decision_counts,
        target_state: value.target_state.clone(),
        observed_state: value.observed_state.clone(),
        effective_state: value.effective_state.clone(),
    }
}

fn valid_controller_state(value: &str) -> bool {
    matches!(
        value,
        "not_reported_by_controller_store"
            | "not_reported"
            | "not_computed"
            | "no_registered_adapters"
            | "observation_failed"
            | "observed_without_convergence_receipt"
            | "converged"
            | "failed"
            | "partially_converged"
            | "generation_mismatch"
    )
}

fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn adapter_summary(value: &AdapterInspectionV1) -> DiagnosticAdapterV1 {
    let mut result = DiagnosticAdapterV1 {
        target_count: value.entries.len() as u64,
        converged: 0,
        partial: 0,
        failed: 0,
        unknown: 0,
        reason_codes: value
            .entries
            .iter()
            .map(|entry| entry.reason_code.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    for entry in &value.entries {
        match entry.convergence_state {
            Some(crate::ConvergenceState::Converged) => result.converged += 1,
            Some(crate::ConvergenceState::PartiallyConverged) => result.partial += 1,
            Some(crate::ConvergenceState::Failed) => result.failed += 1,
            None => result.unknown += 1,
        }
    }
    result
}

fn rollout_summary(value: &ConvergenceStatusV1) -> DiagnosticRolloutV1 {
    let mut target_counts = BTreeMap::new();
    for target in &value.targets {
        let state = match target.state {
            TargetRunState::Pending => "pending",
            TargetRunState::Running => "running",
            TargetRunState::Converged => "converged",
            TargetRunState::Deferred => "deferred",
            TargetRunState::Rejected => "rejected",
            TargetRunState::Failed => "failed",
            TargetRunState::Held => "held",
        };
        *target_counts.entry(state.into()).or_insert(0) += 1;
    }
    DiagnosticRolloutV1 {
        state: value.state.clone(),
        current_batch: value.current_batch,
        target_counts,
        partial_accepted: value.partial_accepted,
    }
}

fn overall(checks: &[DoctorCheckV1]) -> CheckState {
    if checks.iter().any(|check| check.state == CheckState::Fail) {
        CheckState::Fail
    } else if checks
        .iter()
        .any(|check| matches!(check.state, CheckState::Warn | CheckState::NotAvailable))
    {
        CheckState::Warn
    } else {
        CheckState::Pass
    }
}

fn safe_actions(checks: &[DoctorCheckV1]) -> Vec<String> {
    checks
        .iter()
        .filter(|check| check.state != CheckState::Pass)
        .map(|check| match check.check_id.as_str() {
            "assessment" => "REVIEW_ASSESSMENT",
            "controller" => "PROVIDE_OR_REPAIR_CONTROLLER_EVIDENCE",
            "adapter" => "PROVIDE_OR_REFRESH_ADAPTER_EVIDENCE",
            "management_profile" => "REVIEW_MANAGEMENT_PROFILE_COMPATIBILITY",
            "rollout" => "REVIEW_ROLLOUT_CONVERGENCE",
            _ => "REVIEW_DIAGNOSTIC_EVIDENCE",
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn payload_digest(value: &DiagnosticBundleV1) -> Result<String, String> {
    let mut unsigned = value.clone();
    unsigned.payload_digest.clear();
    digest(&unsigned).map_err(|_| "DIAGNOSTIC_DIGEST_FAILED".into())
}

#[allow(clippy::too_many_arguments)]
pub fn create_diagnostic_bundle(
    assessment: &BootstrapAssessmentV1,
    controller: Option<&ControllerSnapshot>,
    adapter: Option<&AdapterInspectionV1>,
    profile: Option<&ManagementProfileV1>,
    requirement: Option<&ManagementProfileRequirementV1>,
    rollout: Option<&ConvergenceStatusV1>,
    now: u64,
) -> Result<DiagnosticBundleV1, String> {
    validate_assessment(assessment, now)?;
    if let Some(controller) = controller {
        if controller.authorizes_mutation
            || controller.schema_version != "1"
            || controller.evidence_class != "local_controller_snapshot"
            || !valid_controller_state(&controller.target_state)
            || !valid_controller_state(&controller.observed_state)
            || !valid_controller_state(&controller.effective_state)
        {
            return Err("DIAGNOSTIC_CONTROLLER_INVALID".into());
        }
    }
    if let Some(adapter) = adapter {
        validate_adapter_inspection(adapter, &BTreeSet::new(), now, 60)
            .map_err(|_| "DIAGNOSTIC_ADAPTER_INVALID")?;
        if adapter
            .entries
            .iter()
            .any(|entry| !valid_reason_code(&entry.reason_code))
        {
            return Err("DIAGNOSTIC_ADAPTER_INVALID".into());
        }
    }
    if requirement.is_some() && profile.is_none() {
        return Err("DIAGNOSTIC_PROFILE_REQUIRED".into());
    }
    let profile_summary = match profile {
        Some(profile) => {
            validate_profile(profile, now).map_err(|_| "DIAGNOSTIC_PROFILE_INVALID")?;
            let digest = profile_digest(profile, now).map_err(|_| "DIAGNOSTIC_PROFILE_INVALID")?;
            let (compatibility, reasons) = match requirement {
                Some(requirement) => {
                    let intersection = intersect_profile(profile, requirement, now)
                        .map_err(|_| "DIAGNOSTIC_PROFILE_INVALID")?;
                    (intersection.compatibility, intersection.reason_codes)
                }
                None => (
                    ProfileCompatibility::Compatible,
                    vec!["PROFILE_VALID".into()],
                ),
            };
            Some(DiagnosticProfileV1 {
                profile_digest: digest,
                compatibility,
                reason_codes: reasons,
            })
        }
        None => None,
    };
    if let Some(rollout) = rollout {
        if rollout.schema_version != ROLLOUT_SCHEMA
            || rollout.authorizes_target_execution
            || rollout.targets.len() > 10_000
        {
            return Err("DIAGNOSTIC_ROLLOUT_INVALID".into());
        }
    }

    let mut report = doctor(
        assessment,
        now,
        controller.map(|_| true),
        adapter.map(|_| true),
    );
    report.checks.push(DoctorCheckV1 {
        check_id: "management_profile".into(),
        state: match &profile_summary {
            Some(value) if value.compatibility == ProfileCompatibility::Compatible => {
                CheckState::Pass
            }
            Some(_) => CheckState::Fail,
            None => CheckState::NotAvailable,
        },
        reason_code: match &profile_summary {
            Some(value) if value.compatibility == ProfileCompatibility::Compatible => {
                "MANAGEMENT_PROFILE_COMPATIBLE"
            }
            Some(_) => "MANAGEMENT_PROFILE_INCOMPATIBLE",
            None => "MANAGEMENT_PROFILE_NOT_PROVIDED",
        }
        .into(),
    });
    report.checks.push(DoctorCheckV1 {
        check_id: "rollout".into(),
        state: match rollout.map(|value| &value.state) {
            Some(RunState::Converged) => CheckState::Pass,
            Some(RunState::PartiallyConverged | RunState::Failed) => CheckState::Fail,
            Some(_) => CheckState::Warn,
            None => CheckState::NotAvailable,
        },
        reason_code: match rollout.map(|value| &value.state) {
            Some(RunState::Converged) => "ROLLOUT_CONVERGED",
            Some(RunState::PartiallyConverged) => "ROLLOUT_PARTIALLY_CONVERGED",
            Some(RunState::Failed) => "ROLLOUT_FAILED",
            Some(_) => "ROLLOUT_INCOMPLETE",
            None => "ROLLOUT_NOT_PROVIDED",
        }
        .into(),
    });

    let assessment_digest = digest(assessment).map_err(|_| "DIAGNOSTIC_DIGEST_FAILED")?;
    let mut expires_at = assessment.expires_at;
    if let Some(adapter) = adapter {
        expires_at = expires_at.min(adapter.expires_at);
    }
    if let Some(profile) = profile {
        expires_at = expires_at.min(profile.validity.expires_at);
    }
    let artifacts = vec![
        artifact(
            "bootstrap_assessment",
            Some(assessment),
            Some(assessment.observed_at),
            Some(assessment.expires_at),
        )?,
        artifact("controller_snapshot", controller, None, None)?,
        artifact(
            "adapter_inspection",
            adapter,
            adapter.map(|value| value.observed_at),
            adapter.map(|value| value.expires_at),
        )?,
        artifact(
            "management_profile",
            profile,
            profile.map(|value| value.validity.issued_at),
            profile.map(|value| value.validity.expires_at),
        )?,
        artifact("rollout_status", rollout, None, None)?,
    ];
    let diagnostic_overall = overall(&report.checks);
    let next_actions = safe_actions(&report.checks);
    let mut bundle = DiagnosticBundleV1 {
        schema_version: DIAGNOSTIC_SCHEMA.into(),
        bundle_id: format!("diagnostic:{}", &assessment_digest[7..23]),
        evidence_class: DIAGNOSTIC_EVIDENCE_CLASS.into(),
        tool_version: format!("iicp-management-core/{}", env!("CARGO_PKG_VERSION")),
        created_at: now,
        expires_at,
        authorizes_mutation: false,
        overall: diagnostic_overall,
        artifacts,
        checks: report.checks,
        controller: controller.map(controller_summary),
        adapter: adapter.map(adapter_summary),
        profile: profile_summary,
        rollout: rollout.map(rollout_summary),
        safe_next_actions: next_actions,
        payload_digest: String::new(),
    };
    bundle.payload_digest = payload_digest(&bundle)?;
    validate_diagnostic_bundle(&bundle, now)?;
    Ok(bundle)
}

pub fn validate_diagnostic_bundle(value: &DiagnosticBundleV1, now: u64) -> Result<(), String> {
    if value.schema_version != DIAGNOSTIC_SCHEMA
        || value.evidence_class != DIAGNOSTIC_EVIDENCE_CLASS
        || value.authorizes_mutation
        || value.bundle_id.is_empty()
        || value.tool_version.is_empty()
        || value.created_at > now
        || now > value.expires_at
        || value.artifacts.len() != 5
        || value.checks.len() > 64
        || value.safe_next_actions.len() > 64
        || value
            .checks
            .iter()
            .any(|check| !valid_reason_code(&check.reason_code))
        || value.adapter.as_ref().is_some_and(|adapter| {
            adapter
                .reason_codes
                .iter()
                .any(|reason| !valid_reason_code(reason))
        })
        || value.controller.as_ref().is_some_and(|controller| {
            !valid_controller_state(&controller.target_state)
                || !valid_controller_state(&controller.observed_state)
                || !valid_controller_state(&controller.effective_state)
        })
        || value.payload_digest != payload_digest(value)?
    {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    let kinds = value
        .artifacts
        .iter()
        .map(|artifact| artifact.kind.as_str())
        .collect::<BTreeSet<_>>();
    if kinds.len() != value.artifacts.len()
        || value.artifacts.iter().any(|artifact| match artifact.state {
            DiagnosticArtifactState::Valid => artifact.source_digest.is_none(),
            DiagnosticArtifactState::NotAvailable => artifact.source_digest.is_some(),
        })
        || overall(&value.checks) != value.overall
        || safe_actions(&value.checks) != value.safe_next_actions
    {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    Ok(())
}

fn runtime_state_counts<T: Serialize>(
    values: impl Iterator<Item = T>,
) -> Result<BTreeMap<String, u64>, String> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(enum_string(&value)?).or_insert(0) += 1;
    }
    Ok(counts)
}

fn runtime_summary(value: &RuntimeObservationV1) -> Result<DiagnosticRuntimeV1, String> {
    Ok(DiagnosticRuntimeV1 {
        evidence_state: value.evidence_state.clone(),
        reported_liveness: enum_string(&value.reported_liveness)?,
        reported_readiness: enum_string(&value.reported_readiness)?,
        effective_state: value.effective_state.clone(),
        reason_codes: value.reason_codes.clone(),
        subsystem_state_counts: runtime_state_counts(value.subsystems.values().cloned())?,
        external_connectivity_state_counts: runtime_state_counts(
            value.external_connectivity.values().cloned(),
        )?,
    })
}

fn runtime_check(value: &RuntimeObservationV1) -> DoctorCheckV1 {
    let (state, reason_code) = match (&value.evidence_state, &value.effective_state) {
        (RuntimeEvidenceStateV1::Stale, _) => (CheckState::Warn, "RUNTIME_EVIDENCE_STALE"),
        (_, RuntimeEffectiveStateV1::Ready) => (CheckState::Pass, "RUNTIME_READY"),
        (_, RuntimeEffectiveStateV1::Degraded) => (CheckState::Warn, "RUNTIME_DEGRADED"),
        (_, RuntimeEffectiveStateV1::NotReady) => (CheckState::Fail, "RUNTIME_NOT_READY"),
        (_, RuntimeEffectiveStateV1::Unknown) => (CheckState::Warn, "RUNTIME_STATE_UNKNOWN"),
    };
    DoctorCheckV1 {
        check_id: "runtime_health".into(),
        state,
        reason_code: reason_code.into(),
    }
}

fn runtime_action_for_check(check: &DoctorCheckV1) -> Result<&'static str, String> {
    match check.reason_code.as_str() {
        "RUNTIME_READY" if check.state == CheckState::Pass => Ok(""),
        "RUNTIME_EVIDENCE_STALE" if check.state == CheckState::Warn => {
            Ok("REFRESH_RUNTIME_EVIDENCE")
        }
        "RUNTIME_DEGRADED" if check.state == CheckState::Warn => Ok("REVIEW_RUNTIME_DEGRADATION"),
        "RUNTIME_NOT_READY" if check.state == CheckState::Fail => Ok("RESTORE_OR_REVIEW_RUNTIME"),
        "RUNTIME_STATE_UNKNOWN" if check.state == CheckState::Warn => Ok("REVIEW_RUNTIME_EVIDENCE"),
        _ => Err("DIAGNOSTIC_BUNDLE_INVALID".into()),
    }
}

fn runtime_check_from_summary(value: &DiagnosticRuntimeV1) -> Result<DoctorCheckV1, String> {
    let allowed_subsystem_states = [
        "healthy",
        "degraded",
        "recovering",
        "unavailable",
        "not_applicable",
        "unknown",
    ];
    if value.reason_codes.len() > 128
        || value
            .reason_codes
            .iter()
            .any(|reason| reason.is_empty() || reason.len() > 128)
        || value.subsystem_state_counts.len() > allowed_subsystem_states.len()
        || value.external_connectivity_state_counts.len() > allowed_subsystem_states.len()
        || value
            .subsystem_state_counts
            .keys()
            .chain(value.external_connectivity_state_counts.keys())
            .any(|key| !allowed_subsystem_states.contains(&key.as_str()))
        || !matches!(
            value.reported_liveness.as_str(),
            "starting" | "live" | "not_live" | "indeterminate"
        )
        || !matches!(
            value.reported_readiness.as_str(),
            "ready" | "degraded" | "not_ready"
        )
    {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    let expected = if value.evidence_state == RuntimeEvidenceStateV1::Stale {
        RuntimeEffectiveStateV1::Unknown
    } else if value.reported_liveness == "not_live" {
        RuntimeEffectiveStateV1::NotReady
    } else if value.reported_liveness == "indeterminate" {
        RuntimeEffectiveStateV1::Unknown
    } else {
        match value.reported_readiness.as_str() {
            "ready" => RuntimeEffectiveStateV1::Ready,
            "degraded" => RuntimeEffectiveStateV1::Degraded,
            "not_ready" => RuntimeEffectiveStateV1::NotReady,
            _ => return Err("DIAGNOSTIC_BUNDLE_INVALID".into()),
        }
    };
    if value.effective_state != expected {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    let (state, reason_code) = match (&value.evidence_state, &value.effective_state) {
        (RuntimeEvidenceStateV1::Stale, _) => (CheckState::Warn, "RUNTIME_EVIDENCE_STALE"),
        (_, RuntimeEffectiveStateV1::Ready) => (CheckState::Pass, "RUNTIME_READY"),
        (_, RuntimeEffectiveStateV1::Degraded) => (CheckState::Warn, "RUNTIME_DEGRADED"),
        (_, RuntimeEffectiveStateV1::NotReady) => (CheckState::Fail, "RUNTIME_NOT_READY"),
        (_, RuntimeEffectiveStateV1::Unknown) => (CheckState::Warn, "RUNTIME_STATE_UNKNOWN"),
    };
    Ok(DoctorCheckV1 {
        check_id: "runtime_health".into(),
        state,
        reason_code: reason_code.into(),
    })
}

fn safe_actions_v2(checks: &[DoctorCheckV1]) -> Result<Vec<String>, String> {
    let mut actions = BTreeSet::new();
    for check in checks {
        if check.check_id == "runtime_health" {
            let action = runtime_action_for_check(check)?;
            if !action.is_empty() {
                actions.insert(action.to_owned());
            }
        } else if check.state != CheckState::Pass {
            actions.extend(safe_actions(std::slice::from_ref(check)));
        }
    }
    Ok(actions.into_iter().collect())
}

fn payload_digest_v2(value: &DiagnosticBundleV2) -> Result<String, String> {
    let mut unsigned = value.clone();
    unsigned.base.payload_digest.clear();
    digest(&unsigned).map_err(|_| "DIAGNOSTIC_DIGEST_FAILED".into())
}

#[allow(clippy::too_many_arguments)]
pub fn create_diagnostic_bundle_v2(
    assessment: &BootstrapAssessmentV1,
    controller: Option<&ControllerSnapshot>,
    adapter: Option<&AdapterInspectionV1>,
    profile: Option<&ManagementProfileV1>,
    requirement: Option<&ManagementProfileRequirementV1>,
    rollout: Option<&ConvergenceStatusV1>,
    runtime: &RuntimeObservationV1,
    now: u64,
) -> Result<DiagnosticBundleV2, String> {
    validate_runtime_observation(runtime, now).map_err(|_| "DIAGNOSTIC_RUNTIME_INVALID")?;
    let observed_at = DateTime::parse_from_rfc3339(&runtime.observed_at)
        .map_err(|_| "DIAGNOSTIC_RUNTIME_INVALID")?
        .timestamp();
    let expires_at = DateTime::parse_from_rfc3339(&runtime.expires_at)
        .map_err(|_| "DIAGNOSTIC_RUNTIME_INVALID")?
        .timestamp();
    let observed_at = u64::try_from(observed_at).map_err(|_| "DIAGNOSTIC_RUNTIME_INVALID")?;
    let expires_at = u64::try_from(expires_at).map_err(|_| "DIAGNOSTIC_RUNTIME_INVALID")?;
    let mut base = create_diagnostic_bundle(
        assessment,
        controller,
        adapter,
        profile,
        requirement,
        rollout,
        now,
    )?;
    base.schema_version = DIAGNOSTIC_SCHEMA_V2.into();
    if runtime.evidence_state == RuntimeEvidenceStateV1::Current {
        base.expires_at = base.expires_at.min(expires_at);
    }
    base.artifacts.push(DiagnosticArtifactV1 {
        kind: "runtime_observation".into(),
        state: DiagnosticArtifactState::Valid,
        source_digest: Some(runtime.source_digest.clone()),
        observed_at: Some(observed_at),
        expires_at: Some(expires_at),
    });
    base.checks.push(runtime_check(runtime));
    base.overall = overall(&base.checks);
    base.safe_next_actions = safe_actions_v2(&base.checks)?;
    let mut bundle = DiagnosticBundleV2 {
        base,
        runtime: runtime_summary(runtime)?,
    };
    bundle.base.payload_digest = payload_digest_v2(&bundle)?;
    validate_diagnostic_bundle_v2(&bundle, now)?;
    Ok(bundle)
}

pub fn validate_diagnostic_bundle_v2(value: &DiagnosticBundleV2, now: u64) -> Result<(), String> {
    let runtime_check = runtime_check_from_summary(&value.runtime)?;
    let runtime_checks = value
        .base
        .checks
        .iter()
        .filter(|check| check.check_id == "runtime_health")
        .collect::<Vec<_>>();
    if value.base.schema_version != DIAGNOSTIC_SCHEMA_V2
        || value.base.evidence_class != DIAGNOSTIC_EVIDENCE_CLASS
        || value.base.authorizes_mutation
        || value.base.bundle_id.is_empty()
        || value.base.tool_version.is_empty()
        || value.base.created_at > now
        || now > value.base.expires_at
        || value.base.artifacts.len() != 6
        || value.base.checks.len() > 64
        || value.base.safe_next_actions.len() > 64
        || value.base.payload_digest != payload_digest_v2(value)?
        || value
            .base
            .checks
            .iter()
            .any(|check| !valid_reason_code(&check.reason_code))
        || value.base.adapter.as_ref().is_some_and(|adapter| {
            adapter
                .reason_codes
                .iter()
                .any(|reason| !valid_reason_code(reason))
        })
        || value.base.controller.as_ref().is_some_and(|controller| {
            !valid_controller_state(&controller.target_state)
                || !valid_controller_state(&controller.observed_state)
                || !valid_controller_state(&controller.effective_state)
        })
        || runtime_checks.len() != 1
        || runtime_checks[0] != &runtime_check
    {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    let kinds = value
        .base
        .artifacts
        .iter()
        .map(|artifact| artifact.kind.as_str())
        .collect::<BTreeSet<_>>();
    let expected_kinds = BTreeSet::from([
        "bootstrap_assessment",
        "controller_snapshot",
        "adapter_inspection",
        "management_profile",
        "rollout_status",
        "runtime_observation",
    ]);
    let runtime_artifact = value
        .base
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "runtime_observation")
        .ok_or("DIAGNOSTIC_BUNDLE_INVALID")?;
    if kinds != expected_kinds
        || runtime_artifact.state != DiagnosticArtifactState::Valid
        || runtime_artifact.observed_at.is_none()
        || runtime_artifact.expires_at.is_none()
        || value
            .base
            .artifacts
            .iter()
            .any(|artifact| match artifact.state {
                DiagnosticArtifactState::Valid => artifact
                    .source_digest
                    .as_deref()
                    .is_none_or(|digest| !valid_sha256(digest)),
                DiagnosticArtifactState::NotAvailable => artifact.source_digest.is_some(),
            })
        || overall(&value.base.checks) != value.base.overall
        || safe_actions_v2(&value.base.checks)? != value.base.safe_next_actions
    {
        return Err("DIAGNOSTIC_BUNDLE_INVALID".into());
    }
    Ok(())
}
