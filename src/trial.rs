use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const TRIAL_DEFINITION_SCHEMA: &str = "iicp.management-administrator-trial-definition.v2";
pub const TRIAL_SESSION_SCHEMA: &str = "iicp.management-administrator-trial-session.v2";
pub const TRIAL_EVENT_SCHEMA: &str = "iicp.management-administrator-trial-event.v2";
pub const TRIAL_OUTCOME_SCHEMA: &str = "iicp.management-administrator-trial-outcome.v2";
pub const FRICTION_EVIDENCE_V2_SCHEMA: &str = "iicp.management-friction-evidence.v2";
pub const TRIAL_SUMMARY_SCHEMA: &str = "iicp.management-administrator-trial-summary.v2";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TrialWorkflow {
    AddExistingIntelligenceEndpoint,
    CreateAndSimulateSimplePolicy,
    CreateRestrictedTrustDomain,
    DiagnoseFailedResolution,
    RestorePriorPolicyGeneration,
    ConnectNewSite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassV2 {
    ProjectRehearsal,
    RepresentativeObservation,
    IndependentReproduction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdministratorRole {
    InfrastructureAdministrator,
    SystemAdministrator,
    CloudEngineer,
    SecurityEngineer,
    SapAdministrator,
    Developer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PriorIicpExposure {
    None,
    Basic,
    Experienced,
    Contributor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrialPlatform {
    Linux,
    Macos,
    Windows,
    Container,
    Kubernetes,
    OtherDisposable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentShape {
    DisposableLocal,
    DisposableContainer,
    DisposableCluster,
    AirGappedTest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrialEventKind {
    Interaction,
    ExplicitInput,
    ManualSecretTransfer,
    Assistance,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrialOutcomeKind {
    Success,
    Failed,
    Abandoned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantQualificationV2 {
    pub role: AdministratorRole,
    pub prior_iicp_exposure: PriorIicpExposure,
    pub contributed_to_tested_workflow: bool,
    pub consent_recorded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialEnvironmentV2 {
    pub tested_build: String,
    pub platform: TrialPlatform,
    pub deployment_shape: DeploymentShape,
    #[serde(default)]
    pub enabled_management_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialDefinitionV2 {
    pub schema_version: String,
    pub trial_id: String,
    pub evidence_class: EvidenceClassV2,
    pub workflow: TrialWorkflow,
    pub participant: ParticipantQualificationV2,
    pub environment: TrialEnvironmentV2,
    pub authorizes_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialEventV2 {
    pub schema_version: String,
    pub event_id: String,
    pub occurred_at: u64,
    pub kind: TrialEventKind,
    pub phase_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialOutcomeV2 {
    pub schema_version: String,
    pub completed_at: u64,
    pub outcome: TrialOutcomeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_result_digest: Option<String>,
    #[serde(default)]
    pub canonical_test_references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialSessionV2 {
    pub schema_version: String,
    pub definition: TrialDefinitionV2,
    pub started_at: u64,
    #[serde(default)]
    pub events: Vec<TrialEventV2>,
    pub finalized: bool,
    pub authorizes_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrictionEvidenceV2 {
    pub schema_version: String,
    pub evidence_id: String,
    pub evidence_class: EvidenceClassV2,
    pub claim_status: String,
    pub workflow: TrialWorkflow,
    pub participant: ParticipantQualificationV2,
    pub environment: TrialEnvironmentV2,
    pub started_at: u64,
    pub completed_at: u64,
    pub duration_seconds: u64,
    pub interaction_count: u64,
    pub explicit_input_count: u64,
    pub manual_secret_transfer_count: u64,
    pub assistance_count: u64,
    pub outcome: TrialOutcomeKind,
    pub unassisted_success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_result_digest: Option<String>,
    #[serde(default)]
    pub canonical_test_references: Vec<String>,
    pub authorizes_mutation: bool,
    pub release_gate_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialSummaryV2 {
    pub schema_version: String,
    pub workflow: TrialWorkflow,
    pub total_observations: u64,
    pub successful: u64,
    pub failed: u64,
    pub abandoned: u64,
    pub assisted: u64,
    pub completion_rate_basis_points: u64,
    pub duration_min_seconds: u64,
    pub duration_median_seconds: u64,
    pub duration_max_seconds: u64,
    pub representative_observations: u64,
    pub representative_role_count: u64,
    pub evidence_class_counts: BTreeMap<String, u64>,
    pub numerical_threshold_met: bool,
    pub authorizes_mutation: bool,
    pub release_gate_authorized: bool,
}

fn safe_code(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-' | b'/')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_definition(value: &TrialDefinitionV2) -> Result<(), String> {
    if value.schema_version != TRIAL_DEFINITION_SCHEMA
        || value.authorizes_mutation
        || !safe_code(&value.trial_id, 128)
        || !safe_code(&value.environment.tested_build, 128)
        || value.environment.enabled_management_profiles.len() > 64
        || value
            .environment
            .enabled_management_profiles
            .iter()
            .any(|profile| !safe_code(profile, 256))
    {
        return Err("TRIAL_DEFINITION_INVALID".into());
    }
    if value.evidence_class != EvidenceClassV2::ProjectRehearsal
        && (value.participant.contributed_to_tested_workflow
            || value.participant.prior_iicp_exposure == PriorIicpExposure::Contributor
            || !value.participant.consent_recorded)
    {
        return Err("TRIAL_QUALIFICATION_INVALID".into());
    }
    Ok(())
}

pub fn start_trial(definition: TrialDefinitionV2, now: u64) -> Result<TrialSessionV2, String> {
    validate_definition(&definition)?;
    Ok(TrialSessionV2 {
        schema_version: TRIAL_SESSION_SCHEMA.into(),
        definition,
        started_at: now,
        events: Vec::new(),
        finalized: false,
        authorizes_mutation: false,
    })
}

pub fn validate_session(value: &TrialSessionV2) -> Result<(), String> {
    if value.schema_version != TRIAL_SESSION_SCHEMA || value.authorizes_mutation {
        return Err("TRIAL_SESSION_INVALID".into());
    }
    validate_definition(&value.definition)?;
    let mut ids = BTreeSet::new();
    let mut prior = value.started_at;
    for event in &value.events {
        if event.schema_version != TRIAL_EVENT_SCHEMA
            || !safe_code(&event.event_id, 128)
            || !safe_code(&event.phase_code, 128)
            || event.occurred_at < prior
            || !ids.insert(event.event_id.as_str())
        {
            return Err("TRIAL_EVENT_INVALID".into());
        }
        prior = event.occurred_at;
    }
    Ok(())
}

pub fn record_event(session: &mut TrialSessionV2, event: TrialEventV2) -> Result<(), String> {
    validate_session(session)?;
    if session.finalized {
        return Err("TRIAL_ALREADY_FINALIZED".into());
    }
    session.events.push(event);
    if let Err(error) = validate_session(session) {
        session.events.pop();
        return Err(error);
    }
    Ok(())
}

pub fn finish_trial(
    session: &TrialSessionV2,
    outcome: TrialOutcomeV2,
) -> Result<FrictionEvidenceV2, String> {
    validate_session(session)?;
    if session.finalized {
        return Err("TRIAL_ALREADY_FINALIZED".into());
    }
    if outcome.schema_version != TRIAL_OUTCOME_SCHEMA
        || outcome.completed_at < session.started_at
        || session
            .events
            .last()
            .is_some_and(|event| outcome.completed_at < event.occurred_at)
        || outcome
            .machine_result_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
        || outcome.canonical_test_references.len() > 64
        || outcome
            .canonical_test_references
            .iter()
            .any(|reference| !reference.starts_with("test:") || !safe_code(reference, 256))
        || (outcome.outcome == TrialOutcomeKind::Success && outcome.machine_result_digest.is_none())
    {
        return Err("TRIAL_OUTCOME_INVALID".into());
    }
    let count = |kind| {
        session
            .events
            .iter()
            .filter(|event| event.kind == kind)
            .count() as u64
    };
    let assistance_count = count(TrialEventKind::Assistance);
    let evidence = FrictionEvidenceV2 {
        schema_version: FRICTION_EVIDENCE_V2_SCHEMA.into(),
        evidence_id: format!("evidence:{}", session.definition.trial_id),
        evidence_class: session.definition.evidence_class,
        claim_status: "observer_declared".into(),
        workflow: session.definition.workflow,
        participant: session.definition.participant.clone(),
        environment: session.definition.environment.clone(),
        started_at: session.started_at,
        completed_at: outcome.completed_at,
        duration_seconds: outcome.completed_at - session.started_at,
        interaction_count: count(TrialEventKind::Interaction),
        explicit_input_count: count(TrialEventKind::ExplicitInput),
        manual_secret_transfer_count: count(TrialEventKind::ManualSecretTransfer),
        assistance_count,
        outcome: outcome.outcome,
        unassisted_success: outcome.outcome == TrialOutcomeKind::Success && assistance_count == 0,
        machine_result_digest: outcome.machine_result_digest,
        canonical_test_references: outcome.canonical_test_references,
        authorizes_mutation: false,
        release_gate_authorized: false,
    };
    validate_evidence(&evidence)?;
    Ok(evidence)
}

pub fn validate_evidence(value: &FrictionEvidenceV2) -> Result<(), String> {
    if value.schema_version != FRICTION_EVIDENCE_V2_SCHEMA
        || value.claim_status != "observer_declared"
        || value.authorizes_mutation
        || value.release_gate_authorized
        || !safe_code(&value.evidence_id, 137)
        || value.completed_at < value.started_at
        || value.duration_seconds != value.completed_at - value.started_at
        || value
            .machine_result_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
        || (value.outcome == TrialOutcomeKind::Success && value.machine_result_digest.is_none())
        || value.unassisted_success
            != (value.outcome == TrialOutcomeKind::Success && value.assistance_count == 0)
    {
        return Err("FRICTION_EVIDENCE_V2_INVALID".into());
    }
    validate_definition(&TrialDefinitionV2 {
        schema_version: TRIAL_DEFINITION_SCHEMA.into(),
        trial_id: value
            .evidence_id
            .strip_prefix("evidence:")
            .unwrap_or("")
            .into(),
        evidence_class: value.evidence_class,
        workflow: value.workflow,
        participant: value.participant.clone(),
        environment: value.environment.clone(),
        authorizes_mutation: false,
    })?;
    if value
        .canonical_test_references
        .iter()
        .any(|reference| !reference.starts_with("test:") || !safe_code(reference, 256))
    {
        return Err("FRICTION_EVIDENCE_V2_INVALID".into());
    }
    Ok(())
}

pub fn summarize_trials(values: &[FrictionEvidenceV2]) -> Result<TrialSummaryV2, String> {
    if values.is_empty() {
        return Err("TRIAL_SUMMARY_EMPTY".into());
    }
    for value in values {
        validate_evidence(value)?;
    }
    let workflow = values[0].workflow;
    if values.iter().any(|value| value.workflow != workflow) {
        return Err("TRIAL_SUMMARY_WORKFLOW_MIXED".into());
    }
    let mut durations = values
        .iter()
        .map(|value| value.duration_seconds)
        .collect::<Vec<_>>();
    durations.sort_unstable();
    let middle = durations.len() / 2;
    let median = if durations.len() % 2 == 0 {
        durations[middle - 1] / 2
            + durations[middle] / 2
            + (durations[middle - 1] % 2 + durations[middle] % 2) / 2
    } else {
        durations[middle]
    };
    let successful = values
        .iter()
        .filter(|value| value.outcome == TrialOutcomeKind::Success)
        .count() as u64;
    let failed = values
        .iter()
        .filter(|value| value.outcome == TrialOutcomeKind::Failed)
        .count() as u64;
    let abandoned = values.len() as u64 - successful - failed;
    let assisted = values
        .iter()
        .filter(|value| value.assistance_count > 0)
        .count() as u64;
    let representative = values
        .iter()
        .filter(|value| value.evidence_class == EvidenceClassV2::RepresentativeObservation)
        .collect::<Vec<_>>();
    let roles = representative
        .iter()
        .map(|value| value.participant.role)
        .collect::<BTreeSet<_>>();
    let mut evidence_class_counts = BTreeMap::new();
    for value in values {
        let key = match value.evidence_class {
            EvidenceClassV2::ProjectRehearsal => "project_rehearsal",
            EvidenceClassV2::RepresentativeObservation => "representative_observation",
            EvidenceClassV2::IndependentReproduction => "independent_reproduction",
        };
        *evidence_class_counts.entry(key.into()).or_insert(0) += 1;
    }
    Ok(TrialSummaryV2 {
        schema_version: TRIAL_SUMMARY_SCHEMA.into(),
        workflow,
        total_observations: values.len() as u64,
        successful,
        failed,
        abandoned,
        assisted,
        completion_rate_basis_points: ((successful as u128 * 10_000) / values.len() as u128) as u64,
        duration_min_seconds: durations[0],
        duration_median_seconds: median,
        duration_max_seconds: *durations.last().expect("non-empty"),
        representative_observations: representative.len() as u64,
        representative_role_count: roles.len() as u64,
        evidence_class_counts,
        numerical_threshold_met: representative.len() >= 5 && roles.len() >= 3,
        authorizes_mutation: false,
        release_gate_authorized: false,
    })
}
