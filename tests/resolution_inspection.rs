use iicp_management_core::policy_lifecycle::{
    ApplicationBindingV1, InMemoryPolicyRepository, PolicyDisposition, PolicyReferenceV1,
    PolicyRepository, PolicyRevisionV1,
};
use iicp_management_core::resolution::{
    candidate_eligibility, inspect_resolution, CandidateCompatibilityV1, CandidateEligibilityV1,
    CandidateEvidenceSnapshotV1, CandidateEvidenceV1, ResolutionInspectionError,
    CANDIDATE_EVIDENCE_SCHEMA,
};
use iicp_management_core::ExtensionRequirement;
use jsonschema::validator_for;
use serde_json::{json, Value};

#[derive(serde::Deserialize)]
struct ClassificationFixture {
    cases: Vec<ClassificationCase>,
}

#[derive(serde::Deserialize)]
struct ClassificationCase {
    decision: iicp_management_core::PolicyDecision,
    compatibility: CandidateCompatibilityV1,
    evidence_expired: bool,
    expected: ClassificationExpected,
}

#[derive(serde::Deserialize)]
struct ClassificationExpected {
    eligibility: CandidateEligibilityV1,
    reason_code: Option<String>,
}

fn repository() -> InMemoryPolicyRepository {
    let mut repository = InMemoryPolicyRepository::default();
    repository
        .store_revision(PolicyRevisionV1 {
            schema_version: "1".into(),
            policy_id: "policy:eu".into(),
            revision_id: "r1".into(),
            authority: "domain:test".into(),
            scope: "application:finance".into(),
            disposition: PolicyDisposition::Stored,
            policy: json!({"eq":["region","EU"]}),
            valid_from: None,
            valid_until: None,
            extensions: Vec::<ExtensionRequirement>::new(),
        })
        .unwrap();
    repository
        .store_binding(ApplicationBindingV1 {
            schema_version: "1".into(),
            binding_id: "binding:finance".into(),
            application_id: "application:finance".into(),
            authority: "domain:test".into(),
            policies: vec![PolicyReferenceV1 {
                policy_id: "policy:eu".into(),
                revision_id: "r1".into(),
                authority_rank: 100,
                mandatory: true,
                order: 1,
            }],
            policy_sets: vec![],
            valid_from: None,
            valid_until: None,
            extensions: vec![],
        })
        .unwrap();
    repository
}

fn candidate(
    id: &str,
    compatibility: CandidateCompatibilityV1,
    facts: Value,
) -> CandidateEvidenceV1 {
    CandidateEvidenceV1 {
        candidate_id: id.into(),
        compatibility,
        facts,
    }
}

fn snapshot(candidates: Vec<CandidateEvidenceV1>) -> CandidateEvidenceSnapshotV1 {
    CandidateEvidenceSnapshotV1 {
        schema_version: CANDIDATE_EVIDENCE_SCHEMA.into(),
        snapshot_id: "snapshot:test".into(),
        evidence_source: "fixture".into(),
        observed_at: 100,
        expires_at: 200,
        authorizes_mutation: false,
        candidates,
    }
}

#[test]
fn candidate_eligibility_is_separate_from_compatibility_and_ranking() {
    let output = inspect_resolution(
        &repository(),
        "binding:finance",
        "urn:iicp:intent:finance:invoice-analysis:v1",
        &snapshot(vec![
            candidate(
                "candidate:eligible",
                CandidateCompatibilityV1::Compatible,
                json!({"region":"EU"}),
            ),
            candidate(
                "candidate:denied",
                CandidateCompatibilityV1::Compatible,
                json!({"region":"US"}),
            ),
            candidate(
                "candidate:incompatible",
                CandidateCompatibilityV1::Incompatible,
                json!({"region":"EU"}),
            ),
            candidate(
                "candidate:unknown",
                CandidateCompatibilityV1::Unknown,
                json!({"region":"EU"}),
            ),
        ]),
        150,
    )
    .unwrap();
    assert_eq!(
        (output.eligible, output.ineligible, output.unresolved),
        (1, 2, 1)
    );
    assert!(!output.ranking_applied);
    assert!(!output.authorizes_mutation);
    let states = output
        .entries
        .iter()
        .map(|entry| (&entry.candidate_id, &entry.eligibility))
        .collect::<Vec<_>>();
    assert!(states.contains(&(
        &"candidate:eligible".into(),
        &CandidateEligibilityV1::Eligible
    )));
    assert!(states.contains(&(
        &"candidate:denied".into(),
        &CandidateEligibilityV1::Ineligible
    )));
    assert!(states.contains(&(
        &"candidate:unknown".into(),
        &CandidateEligibilityV1::Unresolved
    )));
}

#[test]
fn stale_and_empty_evidence_remain_truthful() {
    let stale = inspect_resolution(
        &repository(),
        "binding:finance",
        "intent:test",
        &snapshot(vec![candidate(
            "candidate:a",
            CandidateCompatibilityV1::Compatible,
            json!({"region":"EU"}),
        )]),
        201,
    )
    .unwrap();
    assert!(stale.evidence_expired);
    assert_eq!((stale.eligible, stale.unresolved), (0, 1));
    assert!(stale.entries[0]
        .reason_codes
        .contains(&"IICP-MGMT-CANDIDATE-EVIDENCE-STALE".into()));

    let empty = inspect_resolution(
        &repository(),
        "binding:finance",
        "intent:test",
        &snapshot(vec![]),
        150,
    )
    .unwrap();
    assert!(empty.entries.is_empty());
    assert_eq!(
        (empty.eligible, empty.ineligible, empty.unresolved),
        (0, 0, 0)
    );
}

#[test]
fn malformed_duplicate_and_secret_evidence_fail_closed() {
    let duplicate = snapshot(vec![
        candidate(
            "candidate:a",
            CandidateCompatibilityV1::Compatible,
            json!({"region":"EU"}),
        ),
        candidate(
            "candidate:a",
            CandidateCompatibilityV1::Compatible,
            json!({"region":"EU"}),
        ),
    ]);
    assert_eq!(
        inspect_resolution(
            &repository(),
            "binding:finance",
            "intent:test",
            &duplicate,
            150
        ),
        Err(ResolutionInspectionError::DuplicateCandidate)
    );
    let secret = snapshot(vec![candidate(
        "candidate:a",
        CandidateCompatibilityV1::Compatible,
        json!({"api_key":"no"}),
    )]);
    assert_eq!(
        inspect_resolution(
            &repository(),
            "binding:finance",
            "intent:test",
            &secret,
            150
        ),
        Err(ResolutionInspectionError::SecretRejected)
    );
    let mut future = snapshot(vec![]);
    future.observed_at = 151;
    assert_eq!(
        inspect_resolution(
            &repository(),
            "binding:finance",
            "intent:test",
            &future,
            150
        ),
        Err(ResolutionInspectionError::InvalidEvidence)
    );
}

#[test]
fn published_schema_accepts_snapshot_and_inspection() {
    let schema: Value = serde_json::from_str(include_str!(
        "../contracts/resolution-inspection-v1.schema.json"
    ))
    .unwrap();
    let validator = validator_for(&schema).unwrap();
    let snapshot = snapshot(vec![candidate(
        "candidate:a",
        CandidateCompatibilityV1::Compatible,
        json!({"region":"EU"}),
    )]);
    assert!(validator.is_valid(&serde_json::to_value(&snapshot).unwrap()));
    let output = inspect_resolution(
        &repository(),
        "binding:finance",
        "intent:test",
        &snapshot,
        150,
    )
    .unwrap();
    assert!(validator.is_valid(&serde_json::to_value(output).unwrap()));
}

#[test]
fn portable_classification_fixture_matches_rust_contract() {
    let fixture: ClassificationFixture = serde_json::from_str(include_str!(
        "../fixtures/resolution-inspection-conformance-v1.json"
    ))
    .unwrap();
    for case in fixture.cases {
        let (eligibility, reason_code) =
            candidate_eligibility(&case.decision, &case.compatibility, case.evidence_expired);
        assert_eq!(eligibility, case.expected.eligibility);
        assert_eq!(reason_code.map(str::to_owned), case.expected.reason_code);
    }
}
