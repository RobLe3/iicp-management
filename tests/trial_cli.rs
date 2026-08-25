use iicp_management_core::trial::{
    finish_trial, FrictionEvidenceV2, TrialOutcomeV2, TrialSessionV2, TrialSummaryV2,
    TRIAL_DEFINITION_SCHEMA, TRIAL_EVENT_SCHEMA, TRIAL_OUTCOME_SCHEMA,
};
use serde_json::json;
use std::{fs, process::Command};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_iicp-management"))
}

#[test]
fn finish_resumes_after_evidence_was_written_before_session_finalization() {
    let directory = tempfile::tempdir().unwrap();
    let definition = directory.path().join("definition.json");
    let session_path = directory.path().join("session.json");
    let outcome_path = directory.path().join("outcome.json");
    let evidence_path = directory.path().join("evidence.json");
    fs::write(
        &definition,
        serde_json::to_vec_pretty(&json!({
            "schema_version":TRIAL_DEFINITION_SCHEMA,
            "trial_id":"trial:resume:1",
            "evidence_class":"project_rehearsal",
            "workflow":"diagnose_failed_resolution",
            "participant":{"role":"developer","prior_iicp_exposure":"contributor","contributed_to_tested_workflow":true,"consent_recorded":true},
            "environment":{"tested_build":"iicp-management/0.4.0-rc.1","platform":"linux","deployment_shape":"disposable_local","enabled_management_profiles":[]},
            "authorizes_mutation":false
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(cli()
        .args([
            "trial",
            "start",
            definition.to_str().unwrap(),
            "--output",
            session_path.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    let session: TrialSessionV2 =
        serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    let outcome = TrialOutcomeV2 {
        schema_version: TRIAL_OUTCOME_SCHEMA.into(),
        completed_at: session.started_at,
        outcome: iicp_management_core::trial::TrialOutcomeKind::Failed,
        machine_result_digest: None,
        canonical_test_references: vec![],
    };
    let evidence = finish_trial(&session, outcome.clone()).unwrap();
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    fs::write(&outcome_path, serde_json::to_vec_pretty(&outcome).unwrap()).unwrap();
    assert!(cli()
        .args([
            "trial",
            "finish",
            session_path.to_str().unwrap(),
            outcome_path.to_str().unwrap(),
            "--output",
            evidence_path.to_str().unwrap()
        ])
        .status()
        .unwrap()
        .success());
    let finalized: TrialSessionV2 =
        serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    assert!(finalized.finalized);
}

#[test]
fn cli_records_finalizes_verifies_and_summarizes_trial() {
    let directory = tempfile::tempdir().unwrap();
    let definition = directory.path().join("definition.json");
    let session_path = directory.path().join("session.json");
    let event = directory.path().join("event.json");
    let outcome = directory.path().join("outcome.json");
    let evidence_path = directory.path().join("evidence.json");
    let summary_path = directory.path().join("summary.json");
    fs::write(
        &definition,
        serde_json::to_vec_pretty(&json!({
            "schema_version":TRIAL_DEFINITION_SCHEMA,
            "trial_id":"trial:cli:1",
            "evidence_class":"project_rehearsal",
            "workflow":"create_and_simulate_simple_policy",
            "participant":{
                "role":"developer",
                "prior_iicp_exposure":"contributor",
                "contributed_to_tested_workflow":true,
                "consent_recorded":true
            },
            "environment":{
                "tested_build":"iicp-management/0.4.0-rc.1",
                "platform":"linux",
                "deployment_shape":"disposable_local",
                "enabled_management_profiles":[]
            },
            "authorizes_mutation":false
        }))
        .unwrap(),
    )
    .unwrap();
    let start = cli()
        .args([
            "--json",
            "trial",
            "start",
            definition.to_str().unwrap(),
            "--output",
            session_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let session: TrialSessionV2 =
        serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();

    fs::write(
        &event,
        serde_json::to_vec_pretty(&json!({
            "schema_version":TRIAL_EVENT_SCHEMA,
            "event_id":"event:cli:1",
            "occurred_at":session.started_at,
            "kind":"interaction",
            "phase_code":"policy_preview"
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(cli()
        .args([
            "trial",
            "event",
            session_path.to_str().unwrap(),
            event.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    fs::write(
        &outcome,
        serde_json::to_vec_pretty(&json!({
            "schema_version":TRIAL_OUTCOME_SCHEMA,
            "completed_at":session.started_at,
            "outcome":"success",
            "machine_result_digest":format!("sha256:{}", "b".repeat(64)),
            "canonical_test_references":["test:cli:receipt"]
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(cli()
        .args([
            "trial",
            "finish",
            session_path.to_str().unwrap(),
            outcome.to_str().unwrap(),
            "--output",
            evidence_path.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    let finalized: TrialSessionV2 =
        serde_json::from_slice(&fs::read(&session_path).unwrap()).unwrap();
    assert!(finalized.finalized);
    let evidence: FrictionEvidenceV2 =
        serde_json::from_slice(&fs::read(&evidence_path).unwrap()).unwrap();
    assert!(!evidence.release_gate_authorized);

    assert!(cli()
        .args(["trial", "verify", evidence_path.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    assert!(cli()
        .args([
            "trial",
            "summarize",
            evidence_path.to_str().unwrap(),
            "--output",
            summary_path.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    let summary: TrialSummaryV2 =
        serde_json::from_slice(&fs::read(&summary_path).unwrap()).unwrap();
    assert_eq!(summary.total_observations, 1);
    assert!(!summary.numerical_threshold_met);
    assert!(!summary.release_gate_authorized);

    let second_finish = cli()
        .args([
            "trial",
            "finish",
            session_path.to_str().unwrap(),
            outcome.to_str().unwrap(),
            "--output",
            directory.path().join("second.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!second_finish.status.success());
    assert!(String::from_utf8_lossy(&second_finish.stderr).contains("TRIAL_ALREADY_FINALIZED"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&evidence_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
