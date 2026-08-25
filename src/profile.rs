use crate::{digest, ExtensionClass, ExtensionRequirement, POLICY_PROFILE};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MANAGEMENT_PROFILE_SCHEMA: &str = "iicp.management-profile.v1";
pub const MANAGEMENT_PROFILE_QUERY_SCHEMA: &str = "iicp.management-profile-query.v1";
pub const MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA: &str = "iicp.management-profile-requirement.v1";
pub const MANAGEMENT_PROFILE_INTERSECTION_SCHEMA: &str = "iicp.management-profile-intersection.v1";
pub const MANAGEMENT_PROFILE_RESPONSE_SCHEMA: &str = "iicp.management-profile-response.v1";
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileValidityV1 {
    pub issued_at: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProfileV1 {
    pub schema_version: String,
    pub controller_id: String,
    pub administrative_domains: Vec<String>,
    pub api_versions: Vec<String>,
    pub schema_ids: Vec<String>,
    pub canonicalization: Vec<String>,
    pub signature_algorithms: Vec<String>,
    pub operations: Vec<String>,
    pub resource_kinds: Vec<String>,
    pub policy_evaluators: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    pub evidence: Vec<String>,
    pub conformance: Vec<String>,
    pub validity: ProfileValidityV1,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
    pub authorizes_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProfileQueryV1 {
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProfileResponseV1 {
    pub schema_version: String,
    pub profile: ManagementProfileV1,
    pub profile_digest: String,
    pub source: String,
    pub authorizes_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProfileRequirementV1 {
    pub schema_version: String,
    #[serde(default)]
    pub controller_id: Option<String>,
    #[serde(default)]
    pub administrative_domain: Option<String>,
    #[serde(default)]
    pub api_versions: Vec<String>,
    #[serde(default)]
    pub schema_ids: Vec<String>,
    #[serde(default)]
    pub canonicalization: Vec<String>,
    #[serde(default)]
    pub signature_algorithms: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub resource_kinds: Vec<String>,
    #[serde(default)]
    pub policy_evaluators: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<ExtensionRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCompatibility {
    Compatible,
    Incompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProfileIntersectionV1 {
    pub schema_version: String,
    pub profile_digest: String,
    pub compatibility: ProfileCompatibility,
    pub selected_api_versions: Vec<String>,
    pub selected_schema_ids: Vec<String>,
    pub selected_operations: Vec<String>,
    pub selected_resource_kinds: Vec<String>,
    pub selected_policy_evaluators: Vec<String>,
    pub reason_codes: Vec<String>,
    pub authorizes_mutation: bool,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_whitespace)
}

fn valid_set(values: &[String], required: bool) -> bool {
    (!required || !values.is_empty())
        && values.len() <= 1024
        && values.iter().all(|value| valid_id(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

pub fn validate_profile(profile: &ManagementProfileV1, now: u64) -> Result<(), String> {
    if profile.schema_version != MANAGEMENT_PROFILE_SCHEMA
        || !valid_id(&profile.controller_id)
        || profile.authorizes_mutation
        || profile.validity.issued_at > profile.validity.not_before
        || profile.validity.not_before > now
        || now > profile.validity.expires_at
        || profile.validity.generation == 0
        || profile.validity.issued_at > MAX_SAFE_JSON_INTEGER
        || profile.validity.not_before > MAX_SAFE_JSON_INTEGER
        || profile.validity.expires_at > MAX_SAFE_JSON_INTEGER
        || !valid_set(&profile.administrative_domains, true)
        || !valid_set(&profile.api_versions, true)
        || !valid_set(&profile.schema_ids, true)
        || !valid_set(&profile.canonicalization, true)
        || !valid_set(&profile.signature_algorithms, true)
        || !valid_set(&profile.operations, true)
        || !valid_set(&profile.resource_kinds, false)
        || !valid_set(&profile.policy_evaluators, true)
        || !valid_set(&profile.evidence, false)
        || !valid_set(&profile.conformance, false)
        || profile.limits.is_empty()
        || profile.limits.len() > 128
        || profile
            .limits
            .iter()
            .any(|(key, value)| !valid_id(key) || *value == 0 || *value > MAX_SAFE_JSON_INTEGER)
    {
        return Err("MANAGEMENT_PROFILE_INVALID".into());
    }
    if profile.extensions.len() > 128
        || profile.extensions.iter().any(|item| !valid_id(&item.id))
        || profile
            .extensions
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != profile.extensions.len()
    {
        return Err("MANAGEMENT_PROFILE_EXTENSION_INVALID".into());
    }
    Ok(())
}

pub fn profile_digest(profile: &ManagementProfileV1, now: u64) -> Result<String, String> {
    validate_profile(profile, now)?;
    digest(profile).map_err(|error| error.to_string())
}

pub fn controller_profile(
    controller_id: &str,
    administrative_domain: &str,
    operations: BTreeSet<String>,
    resource_kinds: BTreeSet<String>,
    _now: u64,
) -> ManagementProfileV1 {
    ManagementProfileV1 {
        schema_version: MANAGEMENT_PROFILE_SCHEMA.into(),
        controller_id: controller_id.into(),
        administrative_domains: vec![administrative_domain.into()],
        api_versions: vec!["management-local-ipc/v1".into()],
        schema_ids: vec![
            "iicp.management-plan-submission.v1".into(),
            "iicp.management-apply-gate.v1".into(),
            "iicp.management-local-recovery.v1".into(),
            "iicp.management-rollout.v1".into(),
        ],
        canonicalization: vec!["RFC8785-JCS".into()],
        signature_algorithms: vec!["Ed25519".into()],
        operations: operations.into_iter().collect(),
        resource_kinds: resource_kinds.into_iter().collect(),
        policy_evaluators: vec![POLICY_PROFILE.into()],
        limits: BTreeMap::from([
            ("max_document_bytes".into(), 1024 * 1024),
            ("max_operations".into(), 1000),
            ("max_targets".into(), 1000),
        ]),
        evidence: vec![
            "controller-authorization-receipt-v1".into(),
            "adapter-receipt-v1".into(),
            "verification-receipt-v1".into(),
        ],
        conformance: vec!["management-portable-conformance-v1".into()],
        validity: ProfileValidityV1 {
            issued_at: 0,
            not_before: 0,
            expires_at: 4_102_444_800,
            generation: 1,
        },
        extensions: Vec::new(),
        authorizes_mutation: false,
    }
}

fn missing(required: &[String], offered: &[String], label: &str, reasons: &mut Vec<String>) {
    let offered = offered.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for value in required {
        if !offered.contains(value.as_str()) {
            reasons.push(format!("PROFILE_REQUIRED_{label}_UNSUPPORTED:{value}"));
        }
    }
}

fn selected(required: &[String], offered: &[String]) -> Vec<String> {
    let offered = offered.iter().map(String::as_str).collect::<BTreeSet<_>>();
    required
        .iter()
        .filter(|value| offered.contains(value.as_str()))
        .cloned()
        .collect()
}

pub fn intersect_profile(
    profile: &ManagementProfileV1,
    requirement: &ManagementProfileRequirementV1,
    now: u64,
) -> Result<ManagementProfileIntersectionV1, String> {
    validate_profile(profile, now)?;
    if requirement.schema_version != MANAGEMENT_PROFILE_REQUIREMENT_SCHEMA {
        return Err("MANAGEMENT_PROFILE_REQUIREMENT_INVALID".into());
    }
    for values in [
        &requirement.api_versions,
        &requirement.schema_ids,
        &requirement.canonicalization,
        &requirement.signature_algorithms,
        &requirement.operations,
        &requirement.resource_kinds,
        &requirement.policy_evaluators,
    ] {
        if !valid_set(values, false) {
            return Err("MANAGEMENT_PROFILE_REQUIREMENT_INVALID".into());
        }
    }
    if requirement
        .controller_id
        .iter()
        .chain(requirement.administrative_domain.iter())
        .any(|value| !valid_id(value))
        || requirement.extensions.len() > 128
        || requirement
            .extensions
            .iter()
            .any(|item| !valid_id(&item.id))
        || requirement
            .extensions
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != requirement.extensions.len()
    {
        return Err("MANAGEMENT_PROFILE_REQUIREMENT_INVALID".into());
    }
    let mut reasons = Vec::new();
    if requirement
        .controller_id
        .as_ref()
        .is_some_and(|value| value != &profile.controller_id)
    {
        reasons.push("PROFILE_CONTROLLER_MISMATCH".into());
    }
    if requirement
        .administrative_domain
        .as_ref()
        .is_some_and(|value| !profile.administrative_domains.contains(value))
    {
        reasons.push("PROFILE_DOMAIN_UNSUPPORTED".into());
    }
    missing(
        &requirement.api_versions,
        &profile.api_versions,
        "API",
        &mut reasons,
    );
    missing(
        &requirement.schema_ids,
        &profile.schema_ids,
        "SCHEMA",
        &mut reasons,
    );
    missing(
        &requirement.canonicalization,
        &profile.canonicalization,
        "CANONICALIZATION",
        &mut reasons,
    );
    missing(
        &requirement.signature_algorithms,
        &profile.signature_algorithms,
        "SIGNATURE",
        &mut reasons,
    );
    missing(
        &requirement.operations,
        &profile.operations,
        "OPERATION",
        &mut reasons,
    );
    missing(
        &requirement.resource_kinds,
        &profile.resource_kinds,
        "RESOURCE_KIND",
        &mut reasons,
    );
    missing(
        &requirement.policy_evaluators,
        &profile.policy_evaluators,
        "POLICY_EVALUATOR",
        &mut reasons,
    );
    let offered_extensions = profile
        .extensions
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    for extension in &requirement.extensions {
        if !offered_extensions.contains(extension.id.as_str())
            && matches!(
                extension.class,
                ExtensionClass::RequiredUnderstood | ExtensionClass::RequiredSecurityCritical
            )
        {
            reasons.push(format!(
                "PROFILE_REQUIRED_EXTENSION_UNSUPPORTED:{}",
                extension.id
            ));
        }
    }
    reasons.sort();
    reasons.dedup();
    Ok(ManagementProfileIntersectionV1 {
        schema_version: MANAGEMENT_PROFILE_INTERSECTION_SCHEMA.into(),
        profile_digest: profile_digest(profile, now)?,
        compatibility: if reasons.is_empty() {
            ProfileCompatibility::Compatible
        } else {
            ProfileCompatibility::Incompatible
        },
        selected_api_versions: selected(&requirement.api_versions, &profile.api_versions),
        selected_schema_ids: selected(&requirement.schema_ids, &profile.schema_ids),
        selected_operations: selected(&requirement.operations, &profile.operations),
        selected_resource_kinds: selected(&requirement.resource_kinds, &profile.resource_kinds),
        selected_policy_evaluators: selected(
            &requirement.policy_evaluators,
            &profile.policy_evaluators,
        ),
        reason_codes: reasons,
        authorizes_mutation: false,
    })
}
