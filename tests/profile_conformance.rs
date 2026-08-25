use iicp_management_core::profile::{
    intersect_profile, ManagementProfileRequirementV1, ManagementProfileV1, ProfileCompatibility,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    now: u64,
    profile: ManagementProfileV1,
    requirement: ManagementProfileRequirementV1,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    result: String,
    reasons: Vec<String>,
}

#[test]
fn portable_management_profile_cases_match() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../fixtures/management-profile-conformance-v1.json"
    ))
    .unwrap();
    for case in fixture.cases {
        match intersect_profile(&case.profile, &case.requirement, case.now) {
            Ok(result) => {
                let actual = match result.compatibility {
                    ProfileCompatibility::Compatible => "compatible",
                    ProfileCompatibility::Incompatible => "incompatible",
                };
                assert_eq!(actual, case.expected.result, "{}", case.id);
                assert_eq!(result.reason_codes, case.expected.reasons, "{}", case.id);
            }
            Err(reason) => {
                assert_eq!(case.expected.result, "reject", "{}: {reason}", case.id);
                assert_eq!(case.expected.reasons, vec![reason], "{}", case.id);
            }
        }
    }
}
