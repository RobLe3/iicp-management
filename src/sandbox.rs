use crate::{
    adapters::{AdapterHost, AdapterOperation, SyntheticAdapter},
    apply_gate::{
        authorization_signing_bytes, preview_apply, ApplyAuthorizationEvidenceV1, LocalApplyGateV1,
        APPLY_GATE_SCHEMA,
    },
    controller::{Controller, ControllerPolicy, ManagementRequest, SIGNATURE_PROFILE},
    digest,
    execution::{
        execute_authorized, ApplyLifecycleReceiptV1, LocalApplyExecutionV1, EXECUTION_SCHEMA,
    },
    progressive_authority::{
        OperatingMode, PolicyBoundaryAssessment, ProgressiveAuthorityEvidenceV1,
    },
    Operation, Plan, PolicyDecision, PLANNER_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxScenario {
    Success,
    VerificationFailure,
    InterruptedResume,
}

impl SandboxScenario {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "success" => Ok(Self::Success),
            "verification-failure" => Ok(Self::VerificationFailure),
            "interrupted-resume" => Ok(Self::InterruptedResume),
            _ => Err("SANDBOX_SCENARIO_INVALID".into()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthorizedSandboxResultV1 {
    pub schema_version: String,
    pub exercise: String,
    pub scenario: SandboxScenario,
    pub evidence_class: String,
    pub representative: bool,
    pub local_only: bool,
    pub phases: Vec<String>,
    pub preview: crate::apply_gate::ApplyPreviewV1,
    pub lifecycle: ApplyLifecycleReceiptV1,
    pub automatic_retry_permitted: bool,
    pub activated_external_state: bool,
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn run_authorized_sandbox(
    scenario: SandboxScenario,
    now: u64,
) -> Result<AuthorizedSandboxResultV1, String> {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "iicp-management-sandbox-{}-{}",
        std::process::id(),
        now
    )));
    fs::create_dir(&scratch.0).map_err(|_| "SANDBOX_CREATE_FAILED")?;
    let key = SigningKey::from_bytes(&[83; 32]);
    let mut controller = controller_at_generation_one(&scratch.0.join("controller.db"), &key, now)?;
    let gate = gate(&key, scenario, now)?;
    let preview = preview_apply(&gate, now).map_err(|error| error.to_string())?;
    controller
        .authorize_apply_gate(&gate, now)
        .map_err(|error| error.to_string())?;

    let mut adapter = SyntheticAdapter::new();
    adapter.generation = gate.operation.expected_generation;
    if scenario == SandboxScenario::InterruptedResume {
        adapter.generation += 1;
        adapter.state = gate.operation.desired.clone();
        let operation_digest = digest(&gate.operation).map_err(|error| error.to_string())?;
        controller
            .record_execution_phase(
                &gate.request.request_id,
                &operation_digest,
                "started",
                None,
                None,
                now,
            )
            .map_err(|error| error.to_string())?;
    }
    let mut host = AdapterHost::new();
    host.register("target:sandbox", "synthetic-v1", Box::new(adapter));
    let lifecycle = execute_authorized(
        &controller,
        &mut host,
        &LocalApplyExecutionV1 {
            schema_version: EXECUTION_SCHEMA.into(),
            gate,
        },
        now,
    )?;

    Ok(AuthorizedSandboxResultV1 {
        schema_version: "iicp.management-sandbox-result.v1".into(),
        exercise: "authorized-local".into(),
        scenario,
        evidence_class: "project_rehearsal".into(),
        representative: false,
        local_only: true,
        phases: vec![
            "assess".into(),
            "select_template".into(),
            "preview_impact".into(),
            "plan".into(),
            "authorize_exact_operation".into(),
            "execute_synthetic_adapter".into(),
            "verify".into(),
            "record_evidence".into(),
        ],
        preview,
        lifecycle,
        automatic_retry_permitted: false,
        activated_external_state: false,
    })
}

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn sign_request(key: &SigningKey, request: &mut ManagementRequest) -> Result<(), String> {
    let mut value = serde_json::to_value(&*request).map_err(|_| "SANDBOX_SIGNING_FAILED")?;
    value
        .as_object_mut()
        .ok_or("SANDBOX_SIGNING_FAILED")?
        .remove("signature");
    let bytes = serde_jcs::to_vec(&value).map_err(|_| "SANDBOX_SIGNING_FAILED")?;
    request.signature = STANDARD.encode(key.sign(&bytes).to_bytes());
    Ok(())
}

fn gate(key: &SigningKey, scenario: SandboxScenario, now: u64) -> Result<LocalApplyGateV1, String> {
    let desired: Value = match scenario {
        SandboxScenario::VerificationFailure => {
            json!({"enabled":true,"simulate":"irrecoverable_failure"})
        }
        _ => json!({"enabled":true}),
    };
    let desired_digest = digest(&desired).map_err(|error| error.to_string())?;
    let plan = Plan {
        schema_version: "1".into(),
        planner_version: PLANNER_VERSION.into(),
        bundle_id: "bundle:sandbox".into(),
        bundle_digest: sha('a'),
        expected_generation: 0,
        target_generation: 1,
        operations: vec![Operation {
            operation_id: "operation:sandbox".into(),
            resource_id: "target:sandbox".into(),
            action: "update".into(),
            before_digest: sha('b'),
            after_digest: desired_digest.clone(),
            expected_generation: 0,
            target_generation: 1,
            idempotency_key: "idempotency:sandbox".into(),
        }],
    };
    let plan_digest = digest(&plan).map_err(|error| error.to_string())?;
    let operation = AdapterOperation {
        operation_id: "operation:sandbox".into(),
        target_id: "target:sandbox".into(),
        action: "apply".into(),
        plan_digest: plan_digest.clone(),
        desired_digest,
        expected_generation: 1,
        expires_at: now + 60,
        capability: "synthetic-v1".into(),
        desired,
        related_operation_id: None,
    };
    let mut authorization = ApplyAuthorizationEvidenceV1 {
        schema_version: "1".into(),
        authorization_id: "authorization:sandbox".into(),
        issuer_id: "operator:sandbox".into(),
        audience: "controller:sandbox".into(),
        administrative_domain: "domain:sandbox".into(),
        mode: OperatingMode::Confirm,
        plan_digest: plan_digest.clone(),
        operation_digest: digest(&operation).map_err(|error| error.to_string())?,
        policy_generation: 1,
        fact_snapshot_digest: sha('d'),
        policy_boundary: PolicyBoundaryAssessment::Satisfied,
        proposed_decision: PolicyDecision::Allow,
        issued_at: now,
        expires_at: now + 60,
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    authorization.signature = STANDARD.encode(
        key.sign(&authorization_signing_bytes(&authorization).map_err(|e| e.to_string())?)
            .to_bytes(),
    );
    let progressive_authority = ProgressiveAuthorityEvidenceV1 {
        schema_version: "1".into(),
        evidence_id: "evidence:sandbox".into(),
        mode: OperatingMode::Confirm,
        application_id: "application:sandbox".into(),
        intent: "urn:iicp:intent:test:v1".into(),
        policy_generation: 1,
        fact_snapshot_digest: sha('d'),
        observed_at: now,
        actual_decision: None,
        proposed_decision: Some(PolicyDecision::Allow),
        plan_digest: Some(plan_digest.clone()),
        authorization_evidence_digest: Some(
            digest(&authorization).map_err(|error| error.to_string())?,
        ),
        policy_boundary: PolicyBoundaryAssessment::Satisfied,
        may_request_apply: true,
        extensions: vec![],
    };
    let mut request = ManagementRequest {
        schema_version: "1".into(),
        request_id: operation.operation_id.clone(),
        issuer_id: "operator:sandbox".into(),
        audience: "controller:sandbox".into(),
        administrative_domain: "domain:sandbox".into(),
        action: "apply".into(),
        resource_ids: vec![operation.target_id.clone()],
        payload_digest: operation.desired_digest.clone(),
        plan_digest,
        expected_generation: 1,
        issued_at: now,
        expires_at: now + 60,
        nonce: "nonce:sandbox".into(),
        signature_profile: SIGNATURE_PROFILE.into(),
        signature: String::new(),
    };
    sign_request(key, &mut request)?;
    Ok(LocalApplyGateV1 {
        schema_version: APPLY_GATE_SCHEMA.into(),
        request,
        plan,
        operation,
        progressive_authority,
        authorization,
    })
}

fn policy(now: u64) -> ControllerPolicy {
    ControllerPolicy {
        audience: "controller:sandbox".into(),
        domain: "domain:sandbox".into(),
        allowed_actions: BTreeSet::from(["apply".into(), "observe".into()]),
        revocation_checkpoint: now,
        max_checkpoint_age: 3600,
        high_impact_actions: BTreeSet::from(["apply".into()]),
        max_decision_events: 100,
    }
}

fn controller_at_generation_one(
    path: &std::path::Path,
    key: &SigningKey,
    now: u64,
) -> Result<Controller, String> {
    let mut controller = Controller::open(path, policy(now), key.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;
    let mut seed = gate(key, SandboxScenario::Success, now)?.request;
    seed.action = "observe".into();
    seed.resource_ids = vec!["seed".into()];
    seed.payload_digest = sha('e');
    seed.plan_digest = sha('f');
    seed.expected_generation = 0;
    seed.request_id = "seed".into();
    seed.nonce = "nonce:seed".into();
    sign_request(key, &mut seed)?;
    controller.evaluate(&seed, now).map_err(|e| e.to_string())?;
    Ok(controller)
}
