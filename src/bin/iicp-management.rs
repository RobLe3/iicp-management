use base64::{engine::general_purpose::STANDARD, Engine};
use iicp_management_core::adapters::{validate_adapter_inspection, AdapterInspectionV1};
use iicp_management_core::apply_gate::{preview_apply, LocalApplyGateV1};
use iicp_management_core::bootstrap::{
    create_proposal, doctor, validate_assessment, validate_friction, validate_import,
    AssessmentReadiness, BootstrapAssessmentV1, BootstrapRecommendationV1, CheckState,
    EnvironmentMode, EnvironmentObservationV1, FrictionEvidenceV1, ObservationStatus,
    BOOTSTRAP_SCHEMA, FRICTION_SCHEMA,
};
use iicp_management_core::controller::{
    attach_adapter_inspection, inspect_controller_database, validate_plan_submission, Controller,
    DecisionState, LocalPlanSubmissionV1,
};
use iicp_management_core::diagnostics::{
    create_diagnostic_bundle, validate_diagnostic_bundle, DiagnosticBundleV1,
};
use iicp_management_core::execution::{LocalApplyExecutionV1, EXECUTION_SCHEMA};
use iicp_management_core::ipc::{
    execute_apply, execute_recovery, query_profile, request_apply, request_recovery, submit_plan,
};
use iicp_management_core::policy_lifecycle::{
    repository_from_workspace, simulate_policy_change, ApplicationBindingV1,
    InMemoryPolicyRepository, PolicyDisposition, PolicyReferenceV1, PolicyRevisionV1,
    PolicyWorkspaceV1,
};
use iicp_management_core::profile::{
    controller_profile, intersect_profile, profile_digest, validate_profile,
    ManagementProfileRequirementV1, ManagementProfileV1, ProfileCompatibility,
    MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA, MANAGEMENT_PROFILE_RESPONSE_SCHEMA,
};
use iicp_management_core::progressive_authority::OperatingMode;
use iicp_management_core::reconciliation::DriftClass;
use iicp_management_core::recovery::{
    validate_recovery_gate, LocalRecoveryExecutionV1, LocalRecoveryGateV1,
    RECOVERY_EXECUTION_SCHEMA,
};
use iicp_management_core::rollout::{
    validate_manifest, ConvergenceStatusV1, OperationRunV1, PartialAcceptanceV1, RolloutStore,
    RunState,
};
use iicp_management_core::sandbox::{run_authorized_sandbox, SandboxScenario};
use iicp_management_core::templates::{
    builtin_templates, preview_impact, render_template, template_by_id, CompatibilityStatus,
    ImpactCandidateV1, ImpactRequestV1, TemplateRenderRequestV1, IMPACT_SCHEMA,
    TEMPLATE_RENDER_SCHEMA,
};
use iicp_management_core::trial::{
    finish_trial, record_event, start_trial, summarize_trials, validate_evidence,
    FrictionEvidenceV2, TrialDefinitionV2, TrialEventV2, TrialOutcomeV2, TrialSessionV2,
};
use iicp_management_core::{
    plan, validate_bundle, verify_receipt, AcceptedState, DesiredStateBundle, Plan, Receipt,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    process::ExitCode,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutExecutors {
    executors: BTreeMap<String, String>,
}

fn read<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|_| format!("INPUT_READ_FAILED:{path}"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("INPUT_JSON_INVALID:{path}"))
}

fn write_private_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "OUTPUT_SERIALIZATION_FAILED")?;
    let output = Path::new(path);
    if output.exists() {
        return Err("OUTPUT_EXISTS".into());
    }
    let temporary = output.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut file = options
            .open(&temporary)
            .map_err(|_| "OUTPUT_CREATE_FAILED".to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| "OUTPUT_WRITE_FAILED".to_string())?;
        fs::rename(&temporary, output).map_err(|_| "OUTPUT_RENAME_FAILED".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn replace_private_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "OUTPUT_SERIALIZATION_FAILED")?;
    let output = Path::new(path);
    let temporary = output.with_extension(format!("tmp.{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        use std::io::Write;
        let mut file = options
            .open(&temporary)
            .map_err(|_| "OUTPUT_CREATE_FAILED".to_string())?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| "OUTPUT_WRITE_FAILED".to_string())?;
        fs::rename(&temporary, output).map_err(|_| "OUTPUT_RENAME_FAILED".to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn write_or_verify_private_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    if Path::new(path).exists() {
        let existing: Value = read(path)?;
        let expected = serde_json::to_value(value).map_err(|_| "OUTPUT_SERIALIZATION_FAILED")?;
        return if existing == expected {
            replace_private_json(path, value)
        } else {
            Err("OUTPUT_CONFLICT".into())
        };
    }
    write_private_json(path, value)
}

fn repository(path: &str) -> Result<InMemoryPolicyRepository, String> {
    let input: PolicyWorkspaceV1 = read(path)?;
    repository_from_workspace(input).map_err(|error| error.to_string())
}

fn emit<T: Serialize>(value: &T, json_output: bool, summary: impl FnOnce() -> String) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("serializable output")
        );
    } else {
        println!("{}", summary());
    }
}

fn usage() -> &'static str {
    "usage: iicp-management [--json] <completion|validate|plan|diff|simulate|show|explain|verify-receipt|template|impact|bootstrap|doctor|diagnostics|profile|trial|submit-plan|preview-apply|request-apply|execute-apply|preview-recovery|request-recovery|execute-recovery|rollout|controller|evidence> ...\n\
validate <bundle.json>\nplan <bundle.json> <accepted.json>\ndiff <plan.json>\nsimulate <current-workspace.json> <proposed-workspace.json> <facts.json> <binding-id>\n\
show <stored-policies|active-policies|effective-policy> <workspace.json> [facts.json] [binding-id]\n\
show application <application-id> policy brief --binding <binding-id> --workspace <workspace.json> --facts <facts.json>\n\
show routing <intent> --binding <binding-id> --workspace <workspace.json> --facts <facts.json> [--brief] [--preference <value>]\n\
explain decision <workspace.json> <facts.json> <binding-id> <intent> <decision-id>\n\
verify-receipt <receipt.json> <plan.json> <audience>\nadapter inspect <adapter-inspection.json>\n\
template <list|show> [template-id] [revision-id]\n\
template render <render-request.json>\n\
impact preview <impact-request.json>\n\
submit-plan <socket-or-pipe> <submission.json>\n\
preview-apply <apply-request.json>\n\
request-apply <socket-or-pipe> <apply-request.json> <--confirm operation-id|--non-interactive>\n\
execute-apply <socket-or-pipe> <apply-request.json> <--confirm operation-id|--non-interactive>\n\
preview-recovery <recovery-request.json>\n\
request-recovery <socket-or-pipe> <recovery-request.json> <--confirm operation-id|--non-interactive>\n\
execute-recovery <socket-or-pipe> <recovery-request.json> <--confirm operation-id|--non-interactive>\n\
rollout <validate|create|status|pause|resume|run-batch|retry-target|accept-partial|assess-drift|drift-status|propose-reconcile|reconcile-target> ...\n\
bootstrap <assess|export> <assessment.json>\n\
bootstrap proposal <assessment.json> <issuer> <audience> <generation>\n\
bootstrap import <desired-state.json>\n\
bootstrap sandbox [--exercise authorized-local] [--scenario success|verification-failure|interrupted-resume]\n\
doctor <assessment.json> [controller.db] [adapter-inspection.json] [profile.json] [requirement.json]\n\
diagnostics create <assessment.json> --output <bundle.json> [--controller <controller.db>] [--adapter <adapter-inspection.json>] [--profile <profile.json>] [--requirement <requirement.json>] [--rollout-status <status.json>]\n\
diagnostics <verify|show> <bundle.json>\n\
profile <show|verify> <profile.json>\n\
profile intersect <profile.json> <requirement.json>\n\
profile controller <socket-or-pipe>\n\
trial start <definition.json> --output <session.json>\n\
trial event <session.json> <event.json>\n\
trial finish <session.json> <outcome.json> --output <evidence.json>\n\
trial verify <evidence.json>\n\
trial summarize <evidence.json>... --output <summary.json>\n\
controller status <controller.db> [adapter-inspection.json]\nevidence export <controller.db> [adapter-inspection.json]"
}

fn require(args: &[String], count: usize) -> Result<&[String], String> {
    if args.len() == count {
        Ok(args)
    } else {
        Err("USAGE_INVALID".into())
    }
}

#[derive(Default)]
struct InspectionFlags {
    binding: Option<String>,
    workspace: Option<String>,
    facts: Option<String>,
    brief: bool,
    preferences: Vec<String>,
}

fn inspection_flags(args: &[String], routing: bool) -> Result<InspectionFlags, String> {
    let mut output = InspectionFlags::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--binding" | "--workspace" | "--facts" | "--preference" => {
                let flag = args[index].as_str();
                let value = args.get(index + 1).ok_or("USAGE_INVALID")?.clone();
                match flag {
                    "--binding" => {
                        if output.binding.replace(value).is_some() {
                            return Err("USAGE_INVALID".into());
                        }
                    }
                    "--workspace" => {
                        if output.workspace.replace(value).is_some() {
                            return Err("USAGE_INVALID".into());
                        }
                    }
                    "--facts" => {
                        if output.facts.replace(value).is_some() {
                            return Err("USAGE_INVALID".into());
                        }
                    }
                    "--preference" if routing => output.preferences.push(value),
                    "--preference" => return Err("USAGE_INVALID".into()),
                    _ => {}
                }
                index += 2;
            }
            "--brief" if routing && !output.brief => {
                output.brief = true;
                index += 1;
            }
            _ => return Err("USAGE_INVALID".into()),
        }
    }
    if output.binding.is_none() || output.workspace.is_none() || output.facts.is_none() {
        return Err("USAGE_INVALID".into());
    }
    Ok(output)
}

fn run(args: &[String], json_output: bool) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("__complete") {
        if json_output {
            return Err("USAGE_INVALID".into());
        }
        for value in iicp_management_core::completion::candidates(&args[1..]) {
            println!("{value}");
        }
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("completion") {
        if json_output || args.len() != 2 {
            return Err("USAGE_INVALID".into());
        }
        print!("{}", iicp_management_core::completion::script(&args[1])?);
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("validate") => {
            let a = require(&args[1..], 1)?;
            let bundle: DesiredStateBundle = read(&a[0])?;
            validate_bundle(&bundle, &BTreeSet::new(), 10_000).map_err(|e| e.to_string())?;
            let output = json!({"valid":true,"bundle_id":bundle.bundle_id});
            emit(&output, json_output, || "Valid management bundle".into());
        }
        Some("plan") => {
            let a = require(&args[1..], 2)?;
            let bundle: DesiredStateBundle = read(&a[0])?;
            let accepted: AcceptedState = read(&a[1])?;
            let output =
                plan(&bundle, &accepted, &BTreeSet::new(), 10_000).map_err(|e| e.to_string())?;
            let count = output.operations.len();
            let target = output.target_generation;
            emit(&output, json_output, || {
                format!("Plan: {count} operation(s), target generation {target}")
            });
        }
        Some("diff") => {
            let a = require(&args[1..], 1)?;
            let output: Plan = read(&a[0])?;
            let lines = output
                .operations
                .iter()
                .map(|op| {
                    format!(
                        "{} {} {} -> {}",
                        op.action, op.resource_id, op.before_digest, op.after_digest
                    )
                })
                .collect::<Vec<_>>();
            emit(&output.operations, json_output, || lines.join("\n"));
        }
        Some("simulate") => {
            let a = require(&args[1..], 4)?;
            let current = repository(&a[0])?;
            let proposed = repository(&a[1])?;
            let facts: Value = read(&a[2])?;
            let output = simulate_policy_change(
                current
                    .effective_policy(&a[3], &facts)
                    .map_err(|e| e.to_string())?,
                proposed
                    .effective_policy(&a[3], &facts)
                    .map_err(|e| e.to_string())?,
            );
            let changed = output.decision_changed;
            emit(&output, json_output, || {
                format!(
                    "Decision changed: {changed}; current={:?}, proposed={:?}",
                    output.current.decision, output.proposed.decision
                )
            });
        }
        Some("show") => {
            if args.len() < 3 {
                return Err("USAGE_INVALID".into());
            }
            match args[1].as_str() {
                "stored-policies" | "active-policies" => {
                    let repo = repository(&args[2])?;
                    let active = args[1] == "active-policies";
                    let output = repo.policy_inventory(active).map_err(|e| e.to_string())?;
                    let lines = output
                        .entries
                        .iter()
                        .map(|p| {
                            format!(
                                "{}@{} {:?} bindings={}",
                                p.policy_id, p.revision_id, p.disposition, p.active_binding_count
                            )
                        })
                        .collect::<Vec<_>>();
                    emit(&output, json_output, || {
                        if lines.is_empty() {
                            "No policies".into()
                        } else {
                            lines.join("\n")
                        }
                    });
                }
                "effective-policy" => {
                    if args.len() != 5 {
                        return Err("USAGE_INVALID".into());
                    }
                    let repo = repository(&args[2])?;
                    let facts: Value = read(&args[3])?;
                    let output = repo
                        .effective_policy(&args[4], &facts)
                        .map_err(|e| e.to_string())?;
                    let decision = output.decision.clone();
                    let reasons = output.reason_codes.join(", ");
                    emit(&output, json_output, || {
                        format!("Effective policy: {decision:?}\nReasons: {reasons}")
                    });
                }
                "application"
                    if args.get(3).map(String::as_str) == Some("policy")
                        && args.get(4).map(String::as_str) == Some("brief") =>
                {
                    let flags = inspection_flags(&args[5..], false)?;
                    let binding = flags.binding.as_deref().unwrap();
                    let repo = repository(flags.workspace.as_deref().unwrap())?;
                    let facts: Value = read(flags.facts.as_deref().unwrap())?;
                    let output = repo
                        .application_policy_brief(binding, &facts)
                        .map_err(|error| error.to_string())?;
                    if output.application_id != args[2] {
                        return Err("APPLICATION_BINDING_MISMATCH".into());
                    }
                    let application = output.application_id.clone();
                    let binding = output.binding_id.clone();
                    let generation = output
                        .active_generation
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "NOT_ACTIVE".into());
                    let decision = output.effective_policy.decision.clone();
                    let policies = output
                        .effective_policy
                        .sources
                        .iter()
                        .map(|source| {
                            format!(
                                "{}@{} {:?}",
                                source.policy_id, source.revision_id, source.decision
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    emit(&output, json_output, || {
                        format!(
                            "Application: {application}\nBinding: {binding}\nActive generation: {generation}\nDecision: {decision:?}\nPolicies:\n{policies}\nEvidence snapshot: {}",
                            output.effective_policy.fact_snapshot_digest
                        )
                    });
                }
                "routing" => {
                    let flags = inspection_flags(&args[3..], true)?;
                    let binding = flags.binding.as_deref().unwrap();
                    let repo = repository(flags.workspace.as_deref().unwrap())?;
                    let facts: Value = read(flags.facts.as_deref().unwrap())?;
                    let output = repo
                        .resolution_summary(binding, &args[2], &facts, flags.preferences)
                        .map_err(|error| error.to_string())?;
                    let decision = output.decision.clone();
                    let eligible = output.eligible;
                    let intent = output.intent.clone();
                    let preferences = if output.preferences.is_empty() {
                        "none supplied".into()
                    } else {
                        output.preferences.join(", ")
                    };
                    let brief = flags.brief;
                    emit(&output, json_output, || {
                        if brief {
                            format!(
                                "{intent}: {decision:?}; eligible={eligible}; dynamic evidence-bound resolution"
                            )
                        } else {
                            format!(
                                "Intent: {intent}\nResolution: dynamic, evaluated from the supplied evidence snapshot\nDecision: {decision:?}\nEligible: {eligible}\nPreferences: {preferences}\nEffective policy: {}\nEvidence snapshot: {}",
                                output.effective_policy_digest, output.evidence_snapshot_digest
                            )
                        }
                    });
                }
                _ => return Err("USAGE_INVALID".into()),
            }
        }
        Some("explain") if args.get(1).map(String::as_str) == Some("decision") => {
            let a = require(&args[2..], 5)?;
            let repo = repository(&a[0])?;
            let facts: Value = read(&a[1])?;
            let effective = repo
                .effective_policy(&a[2], &facts)
                .map_err(|e| e.to_string())?;
            let output = repo
                .explain_decision(&a[4], &a[3], &effective)
                .map_err(|e| e.to_string())?;
            let decision = output.decision.clone();
            let policies = output.determining_policy_ids.join(", ");
            emit(&output, json_output, || {
                format!("Decision: {decision:?}\nDetermining policies: {policies}")
            });
        }
        Some("verify-receipt") => {
            let a = require(&args[1..], 3)?;
            let receipt: Receipt = read(&a[0])?;
            let plan: Plan = read(&a[1])?;
            verify_receipt(&receipt, &plan, &a[2]).map_err(|e| e.to_string())?;
            let output = json!({"verified":true,"receipt_id":receipt.receipt_id,"effective_state":receipt.effective_state});
            emit(&output, json_output, || {
                format!(
                    "Receipt {} verified: {:?}",
                    receipt.receipt_id, receipt.effective_state
                )
            });
        }
        Some("template") => match args.get(1).map(String::as_str) {
            Some("list") if args.len() == 2 => {
                let output = builtin_templates();
                let lines = output
                    .iter()
                    .map(|item| {
                        format!("{}@{}  {}", item.template_id, item.revision_id, item.title)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                emit(&output, json_output, || lines);
            }
            Some("show") if args.len() == 3 || args.len() == 4 => {
                let revision = args.get(3).map(String::as_str).unwrap_or("r1");
                let output = template_by_id(&args[2], revision)
                    .ok_or_else(|| "TEMPLATE_NOT_FOUND".to_string())?;
                let title = output.title.clone();
                let description = output.description.clone();
                emit(&output, json_output, || format!("{title}\n{description}"));
            }
            Some("render") if args.len() == 3 => {
                let request: TemplateRenderRequestV1 = read(&args[2])?;
                let template = template_by_id(&request.template_id, &request.revision_id)
                    .ok_or_else(|| "TEMPLATE_NOT_FOUND".to_string())?;
                let output = render_template(&template, &request)?;
                emit(&output, true, String::new);
            }
            _ => return Err("USAGE_INVALID".into()),
        },
        Some("impact") if args.get(1).map(String::as_str) == Some("preview") => {
            let a = require(&args[2..], 1)?;
            let request: ImpactRequestV1 = read(&a[0])?;
            let output = preview_impact(&request, Controller::now())?;
            let changed = output.affected_candidates;
            let denied = output.newly_denied;
            let unknown = output.unresolved_evidence;
            emit(&output, json_output, || {
                format!(
                    "Impact preview: {changed} changed, {denied} newly denied, {unknown} unresolved"
                )
            });
        }
        Some("bootstrap") => match args.get(1).map(String::as_str) {
            Some("assess") | Some("export") => {
                let a = require(&args[2..], 1)?;
                let assessment: BootstrapAssessmentV1 = read(&a[0])?;
                validate_assessment(&assessment, Controller::now())?;
                let readiness = assessment.readiness.clone();
                emit(&assessment, json_output || args[1] == "export", || {
                    format!("Bootstrap assessment valid: {readiness:?}; no state activated")
                });
            }
            Some("proposal") => {
                let a = require(&args[2..], 4)?;
                let assessment: BootstrapAssessmentV1 = read(&a[0])?;
                let generation = a[3].parse::<u64>().map_err(|_| "GENERATION_INVALID")?;
                let output =
                    create_proposal(&assessment, &a[1], &a[2], generation, Controller::now())?;
                emit(&output, true, String::new);
            }
            Some("import") => {
                let a = require(&args[2..], 1)?;
                let bundle: DesiredStateBundle = read(&a[0])?;
                let digest = validate_import(&bundle)?;
                let output = json!({"valid":true,"bundle_digest":digest,"authorizes_mutation":false,"activated":false});
                emit(&output, json_output, || {
                    "Import valid; no state activated".into()
                });
            }
            Some("sandbox") if args.get(2).map(String::as_str) == Some("--exercise") => {
                if args.get(3).map(String::as_str) != Some("authorized-local") {
                    return Err("USAGE_INVALID".into());
                }
                let scenario = match args.get(4).map(String::as_str) {
                    None => SandboxScenario::Success,
                    Some("--scenario") if args.len() == 6 => SandboxScenario::parse(&args[5])?,
                    _ => return Err("USAGE_INVALID".into()),
                };
                let output = run_authorized_sandbox(scenario, Controller::now())?;
                let state = format!("{:?}", output.lifecycle.state);
                emit(&output, json_output, || {
                    format!("Authorized local sandbox: {state}")
                });
            }
            Some("sandbox") if args.len() == 2 => {
                let now = Controller::now();
                let assessment = BootstrapAssessmentV1 {
                    schema_version: BOOTSTRAP_SCHEMA.into(),
                    assessment_id: "sandbox".into(),
                    environment_mode: EnvironmentMode::LocalOnly,
                    observed_at: now,
                    expires_at: now + 300,
                    readiness: AssessmentReadiness::ReadyForProposal,
                    authorizes_mutation: false,
                    observations: vec![EnvironmentObservationV1 {
                        observation_id: "synthetic-runtime".into(),
                        kind: "runtime".into(),
                        source: "sandbox_fixture".into(),
                        status: ObservationStatus::Verified,
                        observed_at: now,
                        expires_at: now + 300,
                        evidence_digest: Some(format!("sha256:{}", "a".repeat(64))),
                        details: json!({"capability":"synthetic-v1"}),
                    }],
                    recommendations: vec![BootstrapRecommendationV1 {
                        recommendation_id: "sandbox-resource".into(),
                        reason: "disposable local test".into(),
                        resource: Some(iicp_management_core::ManagedResource {
                            resource_id: "runtime:sandbox".into(),
                            kind: "RuntimeConfigV1".into(),
                            desired: json!({"schema_version":"iicp.runtime-config.v1","runtime_id":"sandbox","enabled":true}),
                            secret_refs: Default::default(),
                        }),
                        requires_decision_ids: vec![],
                    }],
                    required_decisions: vec![],
                };
                validate_assessment(&assessment, now)?;
                let proposal =
                    create_proposal(&assessment, "sandbox", "controller:sandbox", 0, now)?;
                let management_plan = plan(
                    &proposal,
                    &AcceptedState {
                        generation: 0,
                        resource_digests: BTreeMap::new(),
                    },
                    &BTreeSet::new(),
                    1024,
                )
                .map_err(|error| error.to_string())?;
                let template = template_by_id("high-availability", "r1")
                    .ok_or_else(|| "TEMPLATE_NOT_FOUND".to_string())?;
                let rendered = render_template(
                    &template,
                    &TemplateRenderRequestV1 {
                        schema_version: TEMPLATE_RENDER_SCHEMA.into(),
                        template_id: template.template_id.clone(),
                        revision_id: template.revision_id.clone(),
                        authority: "domain:sandbox".into(),
                        scope: "application:sandbox".into(),
                        application_id: "application:sandbox".into(),
                        binding_id: "binding:sandbox".into(),
                        parameters: BTreeMap::new(),
                    },
                )?;
                let current_workspace = PolicyWorkspaceV1 {
                    revisions: vec![PolicyRevisionV1 {
                        schema_version: "1".into(),
                        policy_id: "policy:sandbox-baseline".into(),
                        revision_id: "r1".into(),
                        authority: "domain:sandbox".into(),
                        scope: "application:sandbox".into(),
                        disposition: PolicyDisposition::Stored,
                        policy: json!({"eq":["sandbox",true]}),
                        valid_from: None,
                        valid_until: None,
                        extensions: vec![],
                    }],
                    policy_sets: vec![],
                    binding: ApplicationBindingV1 {
                        schema_version: "1".into(),
                        binding_id: "binding:sandbox".into(),
                        application_id: "application:sandbox".into(),
                        authority: "domain:sandbox".into(),
                        policies: vec![PolicyReferenceV1 {
                            policy_id: "policy:sandbox-baseline".into(),
                            revision_id: "r1".into(),
                            authority_rank: 100,
                            mandatory: true,
                            order: 1,
                        }],
                        policy_sets: vec![],
                        valid_from: None,
                        valid_until: None,
                        extensions: vec![],
                    },
                    activation: None,
                };
                let facts = json!({"sandbox":true,"fallback_available":false});
                let current_repository = repository_from_workspace(current_workspace.clone())
                    .map_err(|error| error.to_string())?;
                let proposed_repository = repository_from_workspace(rendered.workspace.clone())
                    .map_err(|error| error.to_string())?;
                let simulation = simulate_policy_change(
                    current_repository
                        .effective_policy("binding:sandbox", &facts)
                        .map_err(|error| error.to_string())?,
                    proposed_repository
                        .effective_policy("binding:sandbox", &facts)
                        .map_err(|error| error.to_string())?,
                );
                let impact = preview_impact(
                    &ImpactRequestV1 {
                        schema_version: IMPACT_SCHEMA.into(),
                        current: current_workspace,
                        proposed: rendered.workspace.clone(),
                        candidates: vec![ImpactCandidateV1 {
                            candidate_id: "candidate:sandbox".into(),
                            facts,
                            compatibility: CompatibilityStatus::Compatible,
                            metrics: BTreeMap::new(),
                        }],
                    },
                    now,
                )?;
                let friction = FrictionEvidenceV1 {
                    schema_version: FRICTION_SCHEMA.into(),
                    evidence_id: "sandbox:first-success".into(),
                    evidence_class: "project_rehearsal".into(),
                    workflow: "portable_bootstrap_first_success".into(),
                    actor_class: "project_maintainer".into(),
                    started_at: now,
                    completed_at: now,
                    interaction_count: 5,
                    outcome: "template_impact_simulation_and_plan_created".into(),
                    representative: false,
                    authorizes_mutation: false,
                };
                validate_friction(&friction)?;
                let management_profile = controller_profile(
                    "controller:finance-sandbox",
                    "domain:finance",
                    BTreeSet::from(["apply".into(), "observe".into(), "verify".into()]),
                    BTreeSet::from(["runtime-config-v1".into()]),
                    now,
                );
                let profile_requirement = ManagementProfileRequirementV1 {
                    schema_version: MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA.into(),
                    controller_id: Some("controller:finance-sandbox".into()),
                    administrative_domain: Some("domain:finance".into()),
                    api_versions: vec!["management-local-ipc/v1".into()],
                    schema_ids: vec!["iicp.management-apply-gate.v1".into()],
                    canonicalization: vec!["RFC8785-JCS".into()],
                    signature_algorithms: vec!["Ed25519".into()],
                    operations: vec!["apply".into(), "verify".into()],
                    resource_kinds: vec!["runtime-config-v1".into()],
                    policy_evaluators: vec!["iicp.management-policy.typed-v0".into()],
                    extensions: Vec::new(),
                };
                let profile_intersection =
                    intersect_profile(&management_profile, &profile_requirement, now)?;
                let diagnostic_bundle = create_diagnostic_bundle(
                    &assessment,
                    None,
                    None,
                    Some(&management_profile),
                    Some(&profile_requirement),
                    None,
                    now,
                )?;
                let output = json!({
                    "assessment":assessment,
                    "template":template,
                    "rendered_template":rendered,
                    "impact":impact,
                    "simulation":simulation,
                    "proposal":proposal,
                    "plan":management_plan,
                    "management_profile":management_profile,
                    "profile_intersection":profile_intersection,
                    "diagnostic_bundle":diagnostic_bundle,
                    "friction_evidence":friction,
                    "activated":false
                });
                emit(&output, true, String::new);
            }
            _ => return Err("USAGE_INVALID".into()),
        },
        Some("doctor") => {
            if args.len() < 2 || args.len() > 6 {
                return Err("USAGE_INVALID".into());
            }
            let assessment: BootstrapAssessmentV1 = read(&args[1])?;
            let controller_status = args
                .get(2)
                .map(|path| inspect_controller_database(Path::new(path), 1).is_ok());
            let adapter_status = args.get(3).map(|path| {
                read::<AdapterInspectionV1>(path).is_ok_and(|inspection| {
                    validate_adapter_inspection(
                        &inspection,
                        &BTreeSet::new(),
                        Controller::now(),
                        60,
                    )
                    .is_ok()
                })
            });
            let mut output = doctor(
                &assessment,
                Controller::now(),
                controller_status,
                adapter_status,
            );
            if let Some(path) = args.get(4) {
                let profile: ManagementProfileV1 = read(path)?;
                let state = if let Some(requirement_path) = args.get(5) {
                    let requirement: ManagementProfileRequirementV1 = read(requirement_path)?;
                    match intersect_profile(&profile, &requirement, Controller::now()) {
                        Ok(result) if result.compatibility == ProfileCompatibility::Compatible => {
                            CheckState::Pass
                        }
                        Ok(_) => CheckState::Fail,
                        Err(_) => CheckState::Fail,
                    }
                } else if validate_profile(&profile, Controller::now()).is_ok() {
                    CheckState::Pass
                } else {
                    CheckState::Fail
                };
                output
                    .checks
                    .push(iicp_management_core::bootstrap::DoctorCheckV1 {
                        check_id: "management_profile".into(),
                        reason_code: if state == CheckState::Pass {
                            "MANAGEMENT_PROFILE_COMPATIBLE"
                        } else {
                            "MANAGEMENT_PROFILE_INCOMPATIBLE"
                        }
                        .into(),
                        state,
                    });
                output.overall = if output.checks.iter().any(|c| c.state == CheckState::Fail) {
                    CheckState::Fail
                } else if output
                    .checks
                    .iter()
                    .any(|c| matches!(c.state, CheckState::Warn | CheckState::NotAvailable))
                {
                    CheckState::Warn
                } else {
                    CheckState::Pass
                };
            }
            let overall = output.overall.clone();
            emit(&output, json_output, || {
                format!("Management doctor: {overall:?}")
            });
            if overall == CheckState::Fail {
                return Err("DOCTOR_FAILED".into());
            }
        }
        Some("trial") => match args.get(1).map(String::as_str) {
            Some("start") => {
                if args.len() != 5 || args[3] != "--output" {
                    return Err("USAGE_INVALID".into());
                }
                let definition: TrialDefinitionV2 = read(&args[2])?;
                let session = start_trial(definition, Controller::now())?;
                write_private_json(&args[4], &session)?;
                emit(&session, json_output, || {
                    format!("Trial {} started", session.definition.trial_id)
                });
            }
            Some("event") => {
                let a = require(&args[2..], 2)?;
                let mut session: TrialSessionV2 = read(&a[0])?;
                let event: TrialEventV2 = read(&a[1])?;
                record_event(&mut session, event)?;
                replace_private_json(&a[0], &session)?;
                emit(&session, json_output, || {
                    format!("Trial event recorded ({})", session.events.len())
                });
            }
            Some("finish") => {
                if args.len() != 6 || args[4] != "--output" {
                    return Err("USAGE_INVALID".into());
                }
                let mut session: TrialSessionV2 = read(&args[2])?;
                let outcome: TrialOutcomeV2 = read(&args[3])?;
                let evidence = finish_trial(&session, outcome)?;
                write_or_verify_private_json(&args[5], &evidence)?;
                session.finalized = true;
                replace_private_json(&args[2], &session)?;
                emit(&evidence, json_output, || {
                    format!("Trial {} finalized", session.definition.trial_id)
                });
            }
            Some("verify") => {
                let a = require(&args[2..], 1)?;
                let evidence: FrictionEvidenceV2 = read(&a[0])?;
                validate_evidence(&evidence)?;
                let output = json!({
                    "valid": true,
                    "evidence_id": evidence.evidence_id,
                    "claim_status": evidence.claim_status,
                    "authorizes_mutation": false,
                    "release_gate_authorized": false
                });
                emit(&output, json_output, || {
                    "Trial evidence valid (observer-declared)".into()
                });
            }
            Some("summarize") => {
                if args.len() < 5 || args[args.len() - 2] != "--output" {
                    return Err("USAGE_INVALID".into());
                }
                let evidence = args[2..args.len() - 2]
                    .iter()
                    .map(|path| read::<FrictionEvidenceV2>(path))
                    .collect::<Result<Vec<_>, _>>()?;
                let summary = summarize_trials(&evidence)?;
                write_private_json(&args[args.len() - 1], &summary)?;
                emit(&summary, json_output, || {
                    format!(
                        "Trial summary: {} observations; numerical threshold {}",
                        summary.total_observations,
                        if summary.numerical_threshold_met {
                            "met"
                        } else {
                            "not met"
                        }
                    )
                });
            }
            _ => return Err("USAGE_INVALID".into()),
        },
        Some("diagnostics") => match args.get(1).map(String::as_str) {
            Some("create") => {
                if args.len() < 5 {
                    return Err("USAGE_INVALID".into());
                }
                let assessment: BootstrapAssessmentV1 = read(&args[2])?;
                let mut paths = BTreeMap::new();
                let mut index = 3;
                while index < args.len() {
                    let flag = args.get(index).ok_or("USAGE_INVALID")?;
                    let value = args.get(index + 1).ok_or("USAGE_INVALID")?;
                    if !matches!(
                        flag.as_str(),
                        "--output"
                            | "--controller"
                            | "--adapter"
                            | "--profile"
                            | "--requirement"
                            | "--rollout-status"
                    ) || paths.insert(flag.clone(), value.clone()).is_some()
                    {
                        return Err("USAGE_INVALID".into());
                    }
                    index += 2;
                }
                let output_path = paths.get("--output").ok_or("USAGE_INVALID")?;
                let controller = paths
                    .get("--controller")
                    .map(|path| inspect_controller_database(Path::new(path), 100))
                    .transpose()
                    .map_err(|_| "DIAGNOSTIC_CONTROLLER_INVALID")?;
                let adapter = paths
                    .get("--adapter")
                    .map(|path| read::<AdapterInspectionV1>(path))
                    .transpose()?;
                let profile = paths
                    .get("--profile")
                    .map(|path| read::<ManagementProfileV1>(path))
                    .transpose()?;
                let requirement = paths
                    .get("--requirement")
                    .map(|path| read::<ManagementProfileRequirementV1>(path))
                    .transpose()?;
                let rollout = paths
                    .get("--rollout-status")
                    .map(|path| read::<ConvergenceStatusV1>(path))
                    .transpose()?;
                let output = create_diagnostic_bundle(
                    &assessment,
                    controller.as_ref(),
                    adapter.as_ref(),
                    profile.as_ref(),
                    requirement.as_ref(),
                    rollout.as_ref(),
                    Controller::now(),
                )?;
                write_private_json(output_path, &output)?;
                let overall = output.overall.clone();
                let actions = output.safe_next_actions.len();
                emit(&output, json_output, || {
                    format!(
                        "Diagnostic bundle: {overall:?}\nSafe next actions: {actions}\nWritten: {output_path}"
                    )
                });
            }
            Some("verify") => {
                let a = require(&args[2..], 1)?;
                let output: DiagnosticBundleV1 = read(&a[0])?;
                validate_diagnostic_bundle(&output, Controller::now())?;
                let digest = output.payload_digest.clone();
                emit(&output, json_output, || {
                    format!("Diagnostic bundle valid: {digest}")
                });
            }
            Some("show") => {
                let a = require(&args[2..], 1)?;
                let output: DiagnosticBundleV1 = read(&a[0])?;
                validate_diagnostic_bundle(&output, Controller::now())?;
                let overall = output.overall.clone();
                let degraded = output
                    .checks
                    .iter()
                    .filter(|check| check.state != CheckState::Pass)
                    .map(|check| format!("{}: {}", check.check_id, check.reason_code))
                    .collect::<Vec<_>>();
                let actions = output.safe_next_actions.clone();
                emit(&output, json_output, || {
                    format!(
                        "Overall: {overall:?}\nFindings:\n{}\nSafe next actions:\n{}",
                        if degraded.is_empty() {
                            "none".into()
                        } else {
                            degraded.join("\n")
                        },
                        if actions.is_empty() {
                            "none".into()
                        } else {
                            actions.join("\n")
                        }
                    )
                });
            }
            _ => return Err("USAGE_INVALID".into()),
        },
        Some("profile") => match args.get(1).map(String::as_str) {
            Some("show") => {
                let a = require(&args[2..], 1)?;
                let output: ManagementProfileV1 = read(&a[0])?;
                validate_profile(&output, Controller::now())?;
                let id = output.controller_id.clone();
                let digest = profile_digest(&output, Controller::now())?;
                emit(&output, json_output, || {
                    format!("Controller: {id}\nProfile digest: {digest}")
                });
            }
            Some("verify") => {
                let a = require(&args[2..], 1)?;
                let profile: ManagementProfileV1 = read(&a[0])?;
                let profile_digest = profile_digest(&profile, Controller::now())?;
                let output = json!({
                    "valid": true,
                    "profile_digest": profile_digest,
                    "authorizes_mutation": false
                });
                emit(&output, json_output, || {
                    format!("Valid management profile: {profile_digest}")
                });
            }
            Some("intersect") => {
                let a = require(&args[2..], 2)?;
                let profile: ManagementProfileV1 = read(&a[0])?;
                let requirement: ManagementProfileRequirementV1 = read(&a[1])?;
                let output = intersect_profile(&profile, &requirement, Controller::now())?;
                let compatibility = output.compatibility.clone();
                let reasons = output.reason_codes.join(", ");
                emit(&output, json_output, || {
                    format!("Compatibility: {compatibility:?}\nReasons: {reasons}")
                });
                if compatibility == ProfileCompatibility::Incompatible {
                    return Err("PROFILE_INCOMPATIBLE".into());
                }
            }
            Some("controller") => {
                let a = require(&args[2..], 1)?;
                let output = query_profile(Path::new(&a[0]))?;
                if output.schema_version != MANAGEMENT_PROFILE_RESPONSE_SCHEMA
                    || output.authorizes_mutation
                    || output.source != "owner_protected_local_controller"
                {
                    return Err("PROFILE_RESPONSE_INVALID".into());
                }
                let digest = profile_digest(&output.profile, Controller::now())?;
                if digest != output.profile_digest {
                    return Err("PROFILE_RESPONSE_DIGEST_MISMATCH".into());
                }
                emit(&output, json_output, || {
                    format!("Local controller profile: {digest}")
                });
            }
            _ => return Err("USAGE_INVALID".into()),
        },
        Some("submit-plan") => {
            let a = require(&args[1..], 2)?;
            let submission: LocalPlanSubmissionV1 = read(&a[1])?;
            validate_plan_submission(&submission).map_err(|e| e.to_string())?;
            let output = submit_plan(Path::new(&a[0]), &submission)?;
            let decision = output.decision.clone();
            let generation = output.controller_generation;
            let reason = output.reason.clone();
            emit(&output, json_output, || match decision {
                DecisionState::Accepted => format!(
                    "Plan accepted at controller generation {}; no target action was attempted",
                    generation.map_or_else(|| "unknown".into(), |value| value.to_string())
                ),
                DecisionState::Rejected => format!("Plan rejected: {reason}"),
                DecisionState::Deferred => format!("Plan deferred: {reason}"),
                _ => format!("Plan submission returned {decision:?}: {reason}"),
            });
            match output.decision {
                DecisionState::Accepted => {}
                DecisionState::Rejected => return Err("SUBMISSION_REJECTED".into()),
                DecisionState::Deferred => return Err("SUBMISSION_DEFERRED".into()),
                _ => return Err("SUBMISSION_UNKNOWN".into()),
            }
        }
        Some("preview-apply") => {
            let a = require(&args[1..], 1)?;
            let gate: LocalApplyGateV1 = read(&a[0])?;
            let output = preview_apply(&gate, Controller::now()).map_err(|e| e.to_string())?;
            let target = output.target_id.clone();
            let action = output.action.clone();
            let before = output.before_digest.clone();
            let after = output.after_digest.clone();
            let generation = output.controller_generation;
            let policy_generation = output.policy_generation;
            let mode = output.mode.clone();
            emit(&output, json_output, || {
                format!(
                    "Apply preview\nTarget: {target}\nAction: {action}\nChange: {before} -> {after}\nController generation: {generation}\nPolicy generation: {policy_generation}\nMode: {mode:?}"
                )
            });
        }
        Some("request-apply") => {
            if !(args.len() == 4 || args.len() == 5) {
                return Err("USAGE_INVALID".into());
            }
            let gate: LocalApplyGateV1 = read(&args[2])?;
            let preview = preview_apply(&gate, Controller::now()).map_err(|e| e.to_string())?;
            match gate.progressive_authority.mode {
                OperatingMode::Confirm => {
                    if args.len() != 5
                        || args[3] != "--confirm"
                        || args[4] != gate.operation.operation_id
                    {
                        return Err("APPLY_CONFIRMATION_REQUIRED".into());
                    }
                }
                OperatingMode::AutomaticWithinPolicy => {
                    if args.len() != 4 || args[3] != "--non-interactive" {
                        return Err("APPLY_AUTOMATION_AUTHORIZATION_REQUIRED".into());
                    }
                }
                _ => return Err("APPLY_MODE_NOT_AUTHORIZED".into()),
            }
            let output = request_apply(Path::new(&args[1]), &gate)?;
            let decision = output.decision.clone();
            let reason = output.reason.clone();
            let target = preview.target_id;
            emit(&output, json_output, || match decision {
                DecisionState::Accepted => {
                    format!("Apply request for {target} authorized; no target action was attempted")
                }
                DecisionState::Rejected => format!("Apply request rejected: {reason}"),
                DecisionState::Deferred => format!("Apply request deferred: {reason}"),
                _ => format!("Apply request returned {decision:?}: {reason}"),
            });
            match output.decision {
                DecisionState::Accepted => {}
                DecisionState::Rejected => return Err("SUBMISSION_REJECTED".into()),
                DecisionState::Deferred => return Err("SUBMISSION_DEFERRED".into()),
                _ => return Err("SUBMISSION_UNKNOWN".into()),
            }
        }
        Some("execute-apply") => {
            if !(args.len() == 4 || args.len() == 5) {
                return Err("USAGE_INVALID".into());
            }
            let gate: LocalApplyGateV1 = read(&args[2])?;
            let preview = preview_apply(&gate, Controller::now()).map_err(|e| e.to_string())?;
            match gate.progressive_authority.mode {
                OperatingMode::Confirm
                    if args.len() == 5
                        && args[3] == "--confirm"
                        && args[4] == gate.operation.operation_id => {}
                OperatingMode::AutomaticWithinPolicy
                    if args.len() == 4 && args[3] == "--non-interactive" => {}
                OperatingMode::Confirm => return Err("APPLY_CONFIRMATION_REQUIRED".into()),
                OperatingMode::AutomaticWithinPolicy => {
                    return Err("APPLY_AUTOMATION_AUTHORIZATION_REQUIRED".into())
                }
                _ => return Err("APPLY_MODE_NOT_AUTHORIZED".into()),
            }
            let execution = LocalApplyExecutionV1 {
                schema_version: EXECUTION_SCHEMA.into(),
                gate,
            };
            let output = execute_apply(Path::new(&args[1]), &execution)?;
            let state = output.state.clone();
            let reason = output.reason.clone();
            let target = preview.target_id;
            emit(&output, json_output, || {
                format!("Execution for {target}: {state:?} ({reason})")
            });
        }
        Some("preview-recovery") => {
            let a = require(&args[1..], 1)?;
            let gate: LocalRecoveryGateV1 = read(&a[0])?;
            validate_recovery_gate(&gate, Controller::now())?;
            let output = json!({
                "operation_id": gate.operation.operation_id,
                "target_id": gate.operation.target_id,
                "strategy": gate.strategy,
                "expected_generation": gate.operation.expected_generation,
                "expected_result_digest": gate.operation.desired_digest,
                "authorizes_mutation": false
            });
            emit(&output, json_output, || {
                "Recovery preview valid; no target action attempted".into()
            });
        }
        command @ (Some("request-recovery") | Some("execute-recovery")) => {
            if !(args.len() == 4 || args.len() == 5) {
                return Err("USAGE_INVALID".into());
            }
            let gate: LocalRecoveryGateV1 = read(&args[2])?;
            validate_recovery_gate(&gate, Controller::now())?;
            match gate.progressive_authority.mode {
                OperatingMode::Confirm
                    if args.len() == 5
                        && args[3] == "--confirm"
                        && args[4] == gate.operation.operation_id => {}
                OperatingMode::AutomaticWithinPolicy
                    if args.len() == 4 && args[3] == "--non-interactive" => {}
                OperatingMode::Confirm => return Err("RECOVERY_CONFIRMATION_REQUIRED".into()),
                OperatingMode::AutomaticWithinPolicy => {
                    return Err("RECOVERY_AUTOMATION_AUTHORIZATION_REQUIRED".into())
                }
                _ => return Err("RECOVERY_MODE_NOT_AUTHORIZED".into()),
            }
            if command == Some("request-recovery") {
                let output = request_recovery(Path::new(&args[1]), &gate)?;
                emit(&output, json_output, || {
                    format!(
                        "Recovery {} authorized; no target action attempted",
                        gate.operation.operation_id
                    )
                });
            } else {
                let execution = LocalRecoveryExecutionV1 {
                    schema_version: RECOVERY_EXECUTION_SCHEMA.into(),
                    gate,
                };
                let output = execute_recovery(Path::new(&args[1]), &execution)?;
                emit(&output, json_output, || {
                    format!("Recovery {}: {:?}", output.operation_id, output.outcome)
                });
            }
        }
        Some("rollout") => {
            let now = Controller::now();
            match args.get(1).map(String::as_str) {
                Some("validate") => {
                    let a = require(&args[2..], 1)?;
                    let manifest: OperationRunV1 = read(&a[0])?;
                    let digest = validate_manifest(&manifest, now)?;
                    emit(
                        &json!({"valid": true, "run_id": manifest.run_id, "manifest_digest": digest}),
                        json_output,
                        || "Rollout manifest valid; no target action attempted".into(),
                    );
                }
                Some("create") => {
                    let a = require(&args[2..], 2)?;
                    let manifest: OperationRunV1 = read(&a[1])?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let output = store.create(&manifest, now)?;
                    emit(&output, json_output, || {
                        format!("Rollout {} created in {:?}", output.run_id, output.state)
                    });
                }
                Some("status") | Some("pause") | Some("resume") => {
                    let a = require(&args[2..], 2)?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let output = match args[1].as_str() {
                        "status" => store.status(&a[1])?,
                        "pause" => store.pause(&a[1], now)?,
                        _ => store.resume(&a[1], now)?,
                    };
                    emit(&output, json_output, || {
                        format!(
                            "Rollout {}: {:?}, batch {}",
                            output.run_id, output.state, output.current_batch
                        )
                    });
                }
                Some("run-batch") => {
                    let a = require(&args[2..], 5)?;
                    if a[3] != "--confirm" || a[4] != a[1] {
                        return Err("ROLLOUT_CONFIRMATION_REQUIRED".into());
                    }
                    let config: RolloutExecutors = read(&a[2])?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    for target in store.runnable_targets(&a[1])? {
                        store.mark_running(&a[1], &target.target_id, now)?;
                        let result = config
                            .executors
                            .get(&target.executor_ref)
                            .ok_or("ROLLOUT_EXECUTOR_NOT_CONFIGURED".into())
                            .and_then(|endpoint| {
                                execute_apply(
                                    Path::new(endpoint),
                                    &LocalApplyExecutionV1 {
                                        schema_version: EXECUTION_SCHEMA.into(),
                                        gate: target.gate.clone(),
                                    },
                                )
                            });
                        let status = match result {
                            Ok(receipt) => store.record_receipt(
                                &a[1],
                                &target.target_id,
                                &receipt,
                                Controller::now(),
                            )?,
                            Err(error) => store.record_execution_error(
                                &a[1],
                                &target.target_id,
                                &error,
                                Controller::now(),
                            )?,
                        };
                        if status.state == RunState::Paused {
                            break;
                        }
                    }
                    let output = store.status(&a[1])?;
                    emit(&output, json_output, || {
                        format!(
                            "Rollout {}: {:?}, batch {}",
                            output.run_id, output.state, output.current_batch
                        )
                    });
                }
                Some("retry-target") => {
                    let a = require(&args[2..], 6)?;
                    if a[4] != "--confirm" || a[5] != a[1] {
                        return Err("ROLLOUT_CONFIRMATION_REQUIRED".into());
                    }
                    let config: RolloutExecutors = read(&a[3])?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let target = store.prepare_retry(&a[1], &a[2], now)?;
                    let endpoint = config
                        .executors
                        .get(&target.executor_ref)
                        .ok_or("ROLLOUT_EXECUTOR_NOT_CONFIGURED")?;
                    let execution = LocalApplyExecutionV1 {
                        schema_version: EXECUTION_SCHEMA.into(),
                        gate: target.gate,
                    };
                    let output = match execute_apply(Path::new(endpoint), &execution) {
                        Ok(receipt) => {
                            store.record_receipt(&a[1], &a[2], &receipt, Controller::now())?
                        }
                        Err(error) => {
                            store.record_execution_error(&a[1], &a[2], &error, Controller::now())?
                        }
                    };
                    emit(&output, json_output, || {
                        format!("Rollout {} retry: {:?}", output.run_id, output.state)
                    });
                }
                Some("accept-partial") => {
                    let a = require(&args[2..], 3)?;
                    let acceptance: PartialAcceptanceV1 = read(&a[1])?;
                    let key_text = fs::read_to_string(&a[2])
                        .map_err(|_| format!("INPUT_READ_FAILED:{}", a[2]))?;
                    let key_bytes = STANDARD
                        .decode(key_text.trim())
                        .map_err(|_| "PARTIAL_ACCEPTANCE_KEY_INVALID")?;
                    let key: [u8; 32] = key_bytes
                        .try_into()
                        .map_err(|_| "PARTIAL_ACCEPTANCE_KEY_INVALID")?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let output = store.accept_partial(&acceptance, key, now)?;
                    emit(&output, json_output, || {
                        format!("Partial convergence accepted for {}", output.run_id)
                    });
                }
                Some("assess-drift") => {
                    let a = require(&args[2..], 3)?;
                    let inspection: AdapterInspectionV1 = read(&a[2])?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let output = store.assess_drift(&a[1], &inspection, now)?;
                    let drifted = output
                        .assessments
                        .iter()
                        .filter(|value| {
                            value.state == iicp_management_core::reconciliation::DriftState::Drifted
                        })
                        .count();
                    let unknown = output
                        .assessments
                        .iter()
                        .filter(|value| {
                            value.state == iicp_management_core::reconciliation::DriftState::Unknown
                        })
                        .count();
                    emit(&output, json_output, || {
                        format!("Drift assessment: {drifted} drifted, {unknown} unknown")
                    });
                }
                Some("drift-status") => {
                    let a = require(&args[2..], 2)?;
                    let store = RolloutStore::open(Path::new(&a[0]))?;
                    let output = store.drift_status(&a[1])?;
                    emit(&output, json_output, || {
                        output
                            .assessments
                            .iter()
                            .map(|value| {
                                format!("{}: {:?} ({})", value.target_id, value.state, value.reason)
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    });
                }
                Some("propose-reconcile") => {
                    let a = require(&args[2..], 4)?;
                    let drift_class: DriftClass = serde_json::from_value(json!(a[3]))
                        .map_err(|_| "RECONCILIATION_CLASS_INVALID")?;
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    let output =
                        store.create_reconciliation_proposal(&a[1], &a[2], drift_class, now)?;
                    emit(&output, json_output, || {
                        format!(
                            "Proposal {} created; fresh apply authorization required",
                            output.proposal_id
                        )
                    });
                }
                Some("reconcile-target") => {
                    let a = require(&args[2..], 6)?;
                    let gate: LocalApplyGateV1 = read(&a[2])?;
                    if a[4] != "--confirm" || a[5] != gate.operation.operation_id {
                        return Err("RECONCILIATION_CONFIRMATION_REQUIRED".into());
                    }
                    let mut store = RolloutStore::open(Path::new(&a[0]))?;
                    store.validate_reconciliation_gate(&a[1], &gate, now)?;
                    let operation_id = gate.operation.operation_id.clone();
                    let output = execute_apply(
                        Path::new(&a[3]),
                        &LocalApplyExecutionV1 {
                            schema_version: EXECUTION_SCHEMA.into(),
                            gate: gate.clone(),
                        },
                    )?;
                    store.record_reconciliation_receipt(&a[1], &gate, &output, now)?;
                    emit(&output, json_output, || {
                        format!("Reconciliation {operation_id}: {:?}", output.state)
                    });
                }
                _ => return Err("USAGE_INVALID".into()),
            }
        }
        Some("adapter") if args.get(1).map(String::as_str) == Some("inspect") => {
            let a = require(&args[2..], 1)?;
            let output: AdapterInspectionV1 = read(&a[0])?;
            validate_adapter_inspection(&output, &BTreeSet::new(), Controller::now(), 60)
                .map_err(|e| e.to_string())?;
            let count = output.entries.len();
            emit(&output, json_output, || {
                format!("Adapter inspection valid: {count} target binding(s)")
            });
        }
        Some("controller") if args.get(1).map(String::as_str) == Some("status") => {
            if !(args.len() == 3 || args.len() == 4) {
                return Err("USAGE_INVALID".into());
            }
            let mut output =
                inspect_controller_database(Path::new(&args[2]), 20).map_err(|e| e.to_string())?;
            if let Some(path) = args.get(3) {
                let inspection: AdapterInspectionV1 = read(path)?;
                output = attach_adapter_inspection(output, inspection, Controller::now())
                    .map_err(|e| e.to_string())?;
            }
            let generation = output.generation;
            let decisions = output.recent_decisions.len();
            let observed = output.observed_state.clone();
            let effective = output.effective_state.clone();
            emit(&output, json_output, || {
                format!("Controller generation: {generation}\nRecent decisions: {decisions}\nObserved state: {observed}\nEffective state: {effective}")
            });
        }
        Some("evidence") if args.get(1).map(String::as_str) == Some("export") => {
            if !(args.len() == 3 || args.len() == 4) {
                return Err("USAGE_INVALID".into());
            }
            let mut output =
                inspect_controller_database(Path::new(&args[2]), 100).map_err(|e| e.to_string())?;
            if let Some(path) = args.get(3) {
                let inspection: AdapterInspectionV1 = read(path)?;
                output = attach_adapter_inspection(output, inspection, Controller::now())
                    .map_err(|e| e.to_string())?;
            }
            emit(&output, true, String::new);
        }
        _ => return Err("USAGE_INVALID".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let json_output = args.first().map(String::as_str) == Some("--json");
    if json_output {
        args.remove(0);
    }
    match run(&args, json_output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            if error == "USAGE_INVALID" {
                eprintln!("{}", usage());
            }
            ExitCode::from(if error.starts_with("INPUT_") || error == "USAGE_INVALID" {
                2
            } else if error == "SUBMISSION_REJECTED"
                || error.starts_with("APPLY_")
                || error.contains("DENY")
                || error.contains("UNSUPPORTED")
            {
                3
            } else if error == "SUBMISSION_DEFERRED" {
                5
            } else if error.starts_with("PROFILE_") {
                3
            } else {
                4
            })
        }
    }
}
