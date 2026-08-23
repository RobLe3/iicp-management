use iicp_management_core::{evaluate_policy_with_limits, EvaluationLimits, PolicyDecision};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::process::ExitCode;

const BUILT_IN_FIXTURE: &str = include_str!("../../fixtures/management-policy-conformance-v1.json");

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitOverrides {
    policy_bytes: Option<usize>,
    rules: Option<usize>,
    ast_nodes_per_rule: Option<usize>,
    expression_depth: Option<usize>,
    collection_values: Option<usize>,
    context_bytes: Option<usize>,
    reference_depth: Option<usize>,
    fuel: Option<usize>,
    wall_clock_ms: Option<u64>,
}

impl LimitOverrides {
    fn apply(self) -> EvaluationLimits {
        let defaults = EvaluationLimits::default();
        EvaluationLimits {
            policy_bytes: self.policy_bytes.unwrap_or(defaults.policy_bytes),
            rules: self.rules.unwrap_or(defaults.rules),
            ast_nodes_per_rule: self
                .ast_nodes_per_rule
                .unwrap_or(defaults.ast_nodes_per_rule),
            expression_depth: self.expression_depth.unwrap_or(defaults.expression_depth),
            collection_values: self.collection_values.unwrap_or(defaults.collection_values),
            context_bytes: self.context_bytes.unwrap_or(defaults.context_bytes),
            reference_depth: self.reference_depth.unwrap_or(defaults.reference_depth),
            fuel: self.fuel.unwrap_or(defaults.fuel),
            wall_clock: self
                .wall_clock_ms
                .map(std::time::Duration::from_millis)
                .unwrap_or(defaults.wall_clock),
        }
    }
}

#[derive(Serialize)]
struct CaseResult {
    id: String,
    passed: bool,
    actual_decision: String,
    actual_reason_code: String,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    evaluator_profile: &'static str,
    evidence_class: &'static str,
    passed: usize,
    failed: usize,
    cases: Vec<CaseResult>,
}

fn decision_name(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Deny => "deny",
        PolicyDecision::Indeterminate => "indeterminate",
    }
}

fn load_fixture() -> Result<String, String> {
    match env::args().nth(1) {
        Some(path) => fs::read_to_string(&path)
            .map_err(|error| format!("cannot read fixture {path}: {error}")),
        None => Ok(BUILT_IN_FIXTURE.to_string()),
    }
}

fn run(fixture: &str) -> Result<Report, String> {
    let fixture: Value =
        serde_json::from_str(fixture).map_err(|error| format!("invalid fixture JSON: {error}"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "fixture cases must be an array".to_string())?;
    let mut results = Vec::with_capacity(cases.len());
    let mut ids = BTreeSet::new();
    for case in cases {
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| "fixture case is missing a string id".to_string())?;
        if !ids.insert(id.to_string()) {
            return Err(format!("duplicate fixture case id: {id}"));
        }
        let expected = case
            .get("expected")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("case {id} is missing expected output"))?;
        let limits = case
            .get("limits")
            .cloned()
            .map(serde_json::from_value::<LimitOverrides>)
            .transpose()
            .map_err(|error| format!("case {id} has invalid limits: {error}"))?
            .unwrap_or_default()
            .apply();
        let result = evaluate_policy_with_limits(&case["input"], &case["policy"], limits)
            .map_err(|error| format!("case {id} could not be evaluated: {error}"))?;
        let actual_decision = decision_name(&result.decision).to_string();
        let actual_reason_code = result.reason_codes.first().cloned().unwrap_or_default();
        let passed = expected.get("decision").and_then(Value::as_str)
            == Some(actual_decision.as_str())
            && expected
                .get("reason_codes")
                .and_then(Value::as_array)
                .and_then(|reasons| reasons.first())
                .and_then(Value::as_str)
                == Some(actual_reason_code.as_str());
        results.push(CaseResult {
            id: id.to_string(),
            passed,
            actual_decision,
            actual_reason_code,
        });
    }
    let passed = results.iter().filter(|result| result.passed).count();
    Ok(Report {
        schema_version: "1",
        evaluator_profile: "iicp.management-policy.typed-v0",
        evidence_class: "project-verified",
        passed,
        failed: results.len() - passed,
        cases: results,
    })
}

fn main() -> ExitCode {
    let fixture = match load_fixture() {
        Ok(fixture) => fixture,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let report = match run(&fixture) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    match serde_json::to_string_pretty(&report) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("cannot serialize report: {error}");
            return ExitCode::from(2);
        }
    }
    if report.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
