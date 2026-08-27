use iicp_client::{
    CandidateEvidenceV0, CandidateRanker, ClientConfig, IicpError, RankerDecision, RankerRequest,
    TaskRequest,
};
use iicp_management_core::policy_lifecycle::{
    repository_from_workspace, ApplicationBindingV1, InMemoryPolicyRepository, PolicyDisposition,
    PolicyReferenceV1, PolicyRepository, PolicyRevisionV1, PolicyWorkspaceV1,
    POLICY_LIFECYCLE_VERSION,
};
use iicp_management_core::routing_enforcement::{
    project_active_routing_policy, routing_candidate_ref, ManagedIicpClient,
    RoutingCandidateEvidenceV1, RoutingEnforcementError, ROUTING_CANDIDATE_EVIDENCE_SCHEMA,
};
use jsonschema::validator_for;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

async fn environment_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

struct LoopbackNodeEnvironment(Option<OsString>);

impl LoopbackNodeEnvironment {
    fn enable() -> Self {
        let previous = std::env::var_os("IICP_PROXY_ALLOW_LOOPBACK_NODES");
        unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", "1") };
        Self(previous)
    }
}

impl Drop for LoopbackNodeEnvironment {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => unsafe { std::env::set_var("IICP_PROXY_ALLOW_LOOPBACK_NODES", value) },
            None => unsafe { std::env::remove_var("IICP_PROXY_ALLOW_LOOPBACK_NODES") },
        }
    }
}

fn repository_with_policy(policy: Value) -> InMemoryPolicyRepository {
    let revision = PolicyRevisionV1 {
        schema_version: POLICY_LIFECYCLE_VERSION.into(),
        policy_id: "policy:routing-enforcement".into(),
        revision_id: "r1".into(),
        authority: "authority:test".into(),
        scope: "application:test".into(),
        disposition: PolicyDisposition::Stored,
        policy,
        valid_from: None,
        valid_until: None,
        extensions: vec![],
    };
    let binding = ApplicationBindingV1 {
        schema_version: POLICY_LIFECYCLE_VERSION.into(),
        binding_id: "binding:test".into(),
        application_id: "application:test".into(),
        authority: "authority:test".into(),
        policies: vec![PolicyReferenceV1 {
            policy_id: revision.policy_id.clone(),
            revision_id: revision.revision_id.clone(),
            authority_rank: 100,
            mandatory: true,
            order: 1,
        }],
        policy_sets: vec![],
        valid_from: None,
        valid_until: None,
        extensions: vec![],
    };
    let mut repository = repository_from_workspace(PolicyWorkspaceV1 {
        revisions: vec![revision],
        policy_sets: vec![],
        binding,
        activation: None,
    })
    .unwrap();
    let activation = repository
        .activation_for_binding("binding:test", "authority:test", 100, Some(500))
        .unwrap();
    repository.activate(activation).unwrap();
    repository
}

fn repository() -> InMemoryPolicyRepository {
    repository_with_policy(json!({"all":[
        {"in":["region",["eu"]]},
        {"eq":["manifest_identity_level","known_operator"]}
    ]}))
}

fn candidate_evidence() -> RoutingCandidateEvidenceV1 {
    RoutingCandidateEvidenceV1 {
        schema_version: ROUTING_CANDIDATE_EVIDENCE_SCHEMA.into(),
        evidence_source: "iicp_client_discovery".into(),
        observed_at: 110,
        expires_at: 400,
        eligible_candidate_refs: vec![routing_candidate_ref("node-a").unwrap()],
        ineligible_count: 2,
        unresolved_count: 0,
    }
}

fn task(id: &str) -> TaskRequest {
    TaskRequest {
        task_id: id.into(),
        intent: "urn:iicp:intent:llm:chat:v1".into(),
        payload: json!({"messages":[{"role":"user","content":"bounded test"}]}),
        constraints: None,
        route_constraints: None,
        auth: None,
        source_node_id: None,
        routing_policy: None,
    }
}

fn node(id: &str, endpoint: &str, available: bool, region: &str, identity: &str) -> Value {
    json!({
        "node_id": id,
        "endpoint": endpoint,
        "score": 0.9,
        "load": 0.1,
        "available": available,
        "region": region,
        "models": ["model-a"],
        "cx_public_key": {
            "algorithm": "X25519",
            "encoding": "base64url",
            "key": "-LKZgrZEnFMr9ctB3uQDKsME07ZzS4Ce-SapFAePul0",
            "key_id": "cx-test"
        },
        "node_policy_manifest": {
            "manifest_identity_level": identity,
            "verification": {"status":"signed_valid"},
            "retention": {"prompts":"none","responses":"none"}
        }
    })
}

struct CountingRanker(Arc<AtomicUsize>);

impl CandidateRanker for CountingRanker {
    fn rank(
        &self,
        _request: &RankerRequest<'_>,
        _candidates: &[CandidateEvidenceV0],
    ) -> Result<Option<RankerDecision>, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("ranker must not run without an eligible candidate".into())
    }
}

#[test]
fn portable_projection_fixture_matches_rust_contract() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/routing-enforcement-conformance-v1.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["schema"],
        "iicp.management-routing-enforcement-conformance.v1"
    );
    for case in fixture["cases"].as_array().unwrap() {
        let repository = repository_with_policy(case["policy"].clone());
        let mut evidence = serde_json::to_value(candidate_evidence()).unwrap();
        if let Some(overrides) = case["candidate_evidence"].as_object() {
            evidence.as_object_mut().unwrap().extend(overrides.clone());
        }
        let evidence: RoutingCandidateEvidenceV1 = serde_json::from_value(evidence).unwrap();
        let actual =
            project_active_routing_policy(&repository, "binding:test", &evidence, 120, 180);
        if let Some(error) = case["expected_error"].as_str() {
            assert_eq!(actual.unwrap_err().to_string(), error, "{}", case["id"]);
            continue;
        }
        let actual = actual.unwrap();
        assert_eq!(
            actual.deny_all, case["expected"]["deny_all"],
            "{}",
            case["id"]
        );
        assert_eq!(
            actual.routing_policy.allowed_regions,
            case["expected"]["allowed_regions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            "{}",
            case["id"]
        );
        assert_eq!(
            actual.routing_policy.required_manifest_identity_level,
            case["expected"]["required_manifest_identity_level"]
                .as_str()
                .map(str::to_owned),
            "{}",
            case["id"]
        );
    }
}

#[tokio::test]
async fn active_policy_allows_only_a_and_refuses_prohibited_fallbacks() {
    let _guard = environment_lock().await;
    let _loopback_nodes = LoopbackNodeEnvironment::enable();

    let repository = repository();
    let projection =
        project_active_routing_policy(&repository, "binding:test", &candidate_evidence(), 120, 300)
            .unwrap();
    let schema: Value = serde_json::from_str(include_str!(
        "../contracts/routing-enforcement-v1.schema.json"
    ))
    .unwrap();
    assert!(validator_for(&schema)
        .unwrap()
        .is_valid(&serde_json::to_value(&projection).unwrap()));

    let mut directory = mockito::Server::new_async().await;
    let mut provider_a = mockito::Server::new_async().await;
    let mut provider_b = mockito::Server::new_async().await;
    let mut provider_c = mockito::Server::new_async().await;
    let discovery = directory
        .mock("GET", mockito::Matcher::Regex(r"/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 3,
                "nodes": [
                    node("node-a", &provider_a.url(), true, "eu", "known_operator"),
                    node("node-b", &provider_b.url(), true, "us", "known_operator"),
                    node("node-c", &provider_c.url(), true, "eu", "self_attested")
                ]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let a = provider_a
        .mock("POST", "/v1/task")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"task_id":"allowed","status":"success","result":{"ok":true},"metrics":null}"#,
        )
        .expect(1)
        .create_async()
        .await;
    let b = provider_b
        .mock("POST", "/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let c = provider_c
        .mock("POST", "/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let client = ManagedIicpClient::new(
        &repository,
        projection,
        ClientConfig {
            directory_url: directory.url(),
            route_discovery_mode: "legacy".into(),
            routing_strategy: "deterministic".into(),
            ..Default::default()
        },
        150,
    )
    .unwrap();
    let response = client
        .submit(&repository, task("allowed"), 160)
        .await
        .unwrap();
    assert_eq!(response.task_id, "allowed");
    discovery.assert_async().await;
    a.assert_async().await;
    b.assert_async().await;
    c.assert_async().await;
}

#[tokio::test]
async fn unavailable_a_never_falls_back_to_region_or_identity_prohibited_nodes() {
    let _guard = environment_lock().await;
    let _loopback_nodes = LoopbackNodeEnvironment::enable();

    let repository = repository();
    let projection =
        project_active_routing_policy(&repository, "binding:test", &candidate_evidence(), 120, 300)
            .unwrap();
    let mut directory = mockito::Server::new_async().await;
    let provider_a = mockito::Server::new_async().await;
    let mut provider_b = mockito::Server::new_async().await;
    let mut provider_c = mockito::Server::new_async().await;
    let strategies = ["deterministic", "epsilon", "weighted_v1", "softmax_top_k"];
    let discovery = directory
        .mock("GET", mockito::Matcher::Regex(r"/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 3,
                "nodes": [
                    node("node-a", &provider_a.url(), false, "eu", "known_operator"),
                    node("node-b", &provider_b.url(), true, "us", "known_operator"),
                    node("node-c", &provider_c.url(), true, "eu", "self_attested")
                ]
            })
            .to_string(),
        )
        .expect(strategies.len())
        .create_async()
        .await;
    let b = provider_b
        .mock("POST", "/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let c = provider_c
        .mock("POST", "/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let ranker_calls = Arc::new(AtomicUsize::new(0));
    for (index, strategy) in strategies.iter().enumerate() {
        let client = ManagedIicpClient::new(
            &repository,
            projection.clone(),
            ClientConfig {
                directory_url: directory.url(),
                route_discovery_mode: "legacy".into(),
                routing_strategy: (*strategy).into(),
                ..Default::default()
            },
            150,
        )
        .unwrap()
        .with_candidate_ranker(Arc::new(CountingRanker(ranker_calls.clone())));
        let error = client
            .submit(&repository, task(&format!("refused-{index}")), 160)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RoutingEnforcementError::Client(IicpError::PolicyRefused { ref code, .. })
                if code == "IICP-POLICY-ROUTING"
        ));
    }
    assert_eq!(ranker_calls.load(Ordering::SeqCst), 0);
    discovery.assert_async().await;
    b.assert_async().await;
    c.assert_async().await;
}

#[tokio::test]
async fn candidate_outside_bound_management_snapshot_is_refused_before_dispatch() {
    let _guard = environment_lock().await;
    let _loopback_nodes = LoopbackNodeEnvironment::enable();

    let repository = repository();
    let projection =
        project_active_routing_policy(&repository, "binding:test", &candidate_evidence(), 120, 300)
            .unwrap();
    let mut directory = mockito::Server::new_async().await;
    let mut provider_d = mockito::Server::new_async().await;
    let discovery = directory
        .mock("GET", mockito::Matcher::Regex(r"/v1/discover.*".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "count": 1,
                "nodes": [node(
                    "node-d",
                    &provider_d.url(),
                    true,
                    "eu",
                    "known_operator"
                )]
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;
    let provider = provider_d
        .mock("POST", "/v1/task")
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    let client = ManagedIicpClient::new(
        &repository,
        projection,
        ClientConfig {
            directory_url: directory.url(),
            route_discovery_mode: "legacy".into(),
            ..Default::default()
        },
        150,
    )
    .unwrap();
    let error = client
        .submit(&repository, task("snapshot-mismatch"), 160)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RoutingEnforcementError::Client(IicpError::PolicyRefused { ref code, .. })
            if code == "IICP-CANDIDATE-RANKER-REFUSED"
    ));
    discovery.assert_async().await;
    provider.assert_async().await;
}

#[tokio::test]
async fn expired_projection_refuses_before_directory_contact() {
    let repository = repository();
    let projection =
        project_active_routing_policy(&repository, "binding:test", &candidate_evidence(), 120, 180)
            .unwrap();
    let mut directory = mockito::Server::new_async().await;
    let discovery = directory
        .mock("GET", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let client = ManagedIicpClient::new(
        &repository,
        projection,
        ClientConfig {
            directory_url: directory.url(),
            route_discovery_mode: "legacy".into(),
            ..Default::default()
        },
        150,
    )
    .unwrap();
    assert!(matches!(
        client.submit(&repository, task("expired"), 180).await,
        Err(RoutingEnforcementError::Expired)
    ));
    discovery.assert_async().await;
}
