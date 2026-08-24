use iicp_management_core::controller::inspect_controller_database;
use iicp_management_core::policy_lifecycle::{
    simulate_policy_change, ApplicationBindingV1, InMemoryPolicyRepository, PolicyActivationV1,
    PolicyRepository, PolicyRevisionV1, PolicySetV1,
};
use iicp_management_core::{
    plan, validate_bundle, verify_receipt, AcceptedState, DesiredStateBundle, Plan, Receipt,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, env, fs, path::Path, process::ExitCode};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWorkspace {
    #[serde(default)]
    revisions: Vec<PolicyRevisionV1>,
    #[serde(default)]
    policy_sets: Vec<PolicySetV1>,
    binding: ApplicationBindingV1,
    #[serde(default)]
    activation: Option<PolicyActivationV1>,
}

fn read<T: DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|_| format!("INPUT_READ_FAILED:{path}"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("INPUT_JSON_INVALID:{path}"))
}

fn repository(path: &str) -> Result<InMemoryPolicyRepository, String> {
    let input: PolicyWorkspace = read(path)?;
    let mut repository = InMemoryPolicyRepository::default();
    for revision in input.revisions {
        repository
            .store_revision(revision)
            .map_err(|e| e.to_string())?;
    }
    for set in input.policy_sets {
        repository.store_set(set).map_err(|e| e.to_string())?;
    }
    repository
        .store_binding(input.binding)
        .map_err(|e| e.to_string())?;
    if let Some(activation) = input.activation {
        repository.activate(activation).map_err(|e| e.to_string())?;
    }
    Ok(repository)
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
    "usage: iicp-management [--json] <validate|plan|diff|simulate|show|explain|verify-receipt|controller|evidence> ...\n\
validate <bundle.json>\nplan <bundle.json> <accepted.json>\ndiff <plan.json>\nsimulate <current-workspace.json> <proposed-workspace.json> <facts.json> <binding-id>\n\
show <stored-policies|active-policies|effective-policy> <workspace.json> [facts.json] [binding-id]\n\
explain decision <workspace.json> <facts.json> <binding-id> <intent> <decision-id>\n\
verify-receipt <receipt.json> <plan.json> <audience>\ncontroller status <controller.db>\nevidence export <controller.db>"
}

fn require(args: &[String], count: usize) -> Result<&[String], String> {
    if args.len() == count {
        Ok(args)
    } else {
        Err("USAGE_INVALID".into())
    }
}

fn run(args: &[String], json_output: bool) -> Result<(), String> {
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
            let repo = repository(&args[2])?;
            match args[1].as_str() {
                "stored-policies" | "active-policies" => {
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
        Some("controller") if args.get(1).map(String::as_str) == Some("status") => {
            let a = require(&args[2..], 1)?;
            let output =
                inspect_controller_database(Path::new(&a[0]), 20).map_err(|e| e.to_string())?;
            let generation = output.generation;
            let decisions = output.recent_decisions.len();
            emit(&output, json_output, || {
                format!("Controller generation: {generation}\nRecent decisions: {decisions}\nTarget state: not reported by controller store")
            });
        }
        Some("evidence") if args.get(1).map(String::as_str) == Some("export") => {
            let a = require(&args[2..], 1)?;
            let output =
                inspect_controller_database(Path::new(&a[0]), 100).map_err(|e| e.to_string())?;
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
            } else if error.contains("DENY") || error.contains("UNSUPPORTED") {
                3
            } else {
                4
            })
        }
    }
}
