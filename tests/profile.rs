use iicp_management_core::profile::{
    controller_profile, intersect_profile, profile_digest, validate_profile,
    ManagementProfileRequirementV1, ProfileCompatibility, MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA,
};
use iicp_management_core::{ExtensionClass, ExtensionRequirement};
use std::collections::BTreeSet;

fn profile() -> iicp_management_core::profile::ManagementProfileV1 {
    controller_profile(
        "controller:local",
        "domain:finance",
        BTreeSet::from(["apply".into(), "observe".into(), "verify".into()]),
        BTreeSet::from(["runtime-config-v1".into()]),
        1_000,
    )
}

fn requirement() -> ManagementProfileRequirementV1 {
    ManagementProfileRequirementV1 {
        schema_version: MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA.into(),
        controller_id: Some("controller:local".into()),
        administrative_domain: Some("domain:finance".into()),
        api_versions: vec!["management-local-ipc/v1".into()],
        schema_ids: vec!["iicp.management-apply-gate.v1".into()],
        canonicalization: vec!["RFC8785-JCS".into()],
        signature_algorithms: vec!["Ed25519".into()],
        operations: vec!["apply".into()],
        resource_kinds: vec!["runtime-config-v1".into()],
        policy_evaluators: vec!["iicp.management-policy.typed-v0".into()],
        extensions: Vec::new(),
    }
}

#[test]
fn generated_profile_is_valid_stable_and_non_authorizing() {
    let first = profile();
    let second = controller_profile(
        "controller:local",
        "domain:finance",
        BTreeSet::from(["apply".into(), "observe".into(), "verify".into()]),
        BTreeSet::from(["runtime-config-v1".into()]),
        50_000,
    );
    validate_profile(&first, 1_000).unwrap();
    assert!(!first.authorizes_mutation);
    assert_eq!(
        profile_digest(&first, 1_000),
        profile_digest(&second, 50_000)
    );
}

#[test]
fn exact_intersection_is_compatible_and_non_authorizing() {
    let result = intersect_profile(&profile(), &requirement(), 1_000).unwrap();
    assert_eq!(result.compatibility, ProfileCompatibility::Compatible);
    assert!(result.reason_codes.is_empty());
    assert!(!result.authorizes_mutation);
}

#[test]
fn unsupported_operation_and_security_extension_fail_closed() {
    let mut required = requirement();
    required.operations.push("delete-domain".into());
    required.extensions.push(ExtensionRequirement {
        id: "extension:future-security".into(),
        class: ExtensionClass::RequiredSecurityCritical,
    });
    let result = intersect_profile(&profile(), &required, 1_000).unwrap();
    assert_eq!(result.compatibility, ProfileCompatibility::Incompatible);
    assert!(result
        .reason_codes
        .contains(&"PROFILE_REQUIRED_OPERATION_UNSUPPORTED:delete-domain".into()));
    assert!(result
        .reason_codes
        .contains(&"PROFILE_REQUIRED_EXTENSION_UNSUPPORTED:extension:future-security".into()));
}

#[test]
fn expired_malformed_and_duplicate_profiles_are_rejected() {
    let mut expired = profile();
    expired.validity.expires_at = 999;
    assert_eq!(
        validate_profile(&expired, 1_000),
        Err("MANAGEMENT_PROFILE_INVALID".into())
    );
    let mut duplicate = profile();
    duplicate.operations.push("apply".into());
    assert_eq!(
        validate_profile(&duplicate, 1_000),
        Err("MANAGEMENT_PROFILE_INVALID".into())
    );
}

#[test]
fn published_schemas_accept_reference_profile_and_requirement() {
    let profile_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-profile-v1.schema.json"
    ))
    .unwrap();
    let requirement_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-profile-requirement-v1.schema.json"
    ))
    .unwrap();
    let intersection_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../contracts/management-profile-intersection-v1.schema.json"
    ))
    .unwrap();
    assert!(jsonschema::validator_for(&profile_schema)
        .unwrap()
        .is_valid(&serde_json::to_value(profile()).unwrap()));
    assert!(jsonschema::validator_for(&requirement_schema)
        .unwrap()
        .is_valid(&serde_json::to_value(requirement()).unwrap()));
    let intersection = intersect_profile(&profile(), &requirement(), 1_000).unwrap();
    assert!(jsonschema::validator_for(&intersection_schema)
        .unwrap()
        .is_valid(&serde_json::to_value(intersection).unwrap()));
}
