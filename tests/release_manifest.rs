use jsonschema::validator_for;
use serde_json::{json, Value};
use std::env;
use std::fs;

fn artifact_versions_match(manifest: &Value) -> bool {
    let Some(version) = manifest["version"].as_str() else {
        return false;
    };
    let expected_crate = format!("iicp-management-core-{version}.crate");
    let expected_offline = format!("iicp-management-core-{version}-offline.tar.gz");
    manifest["artifacts"]["crate"]["path"].as_str() == Some(expected_crate.as_str())
        && manifest["artifacts"]["offline_bundle"]["path"].as_str()
            == Some(expected_offline.as_str())
}

#[test]
fn release_manifest_schema_accepts_bounded_non_authorizing_evidence() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string("contracts/management-release-manifest-v1.schema.json").unwrap(),
    )
    .unwrap();
    let validator = validator_for(&schema).unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let manifest = json!({
        "schema": "iicp.management-release-manifest.v1",
        "product": "iicp-management-core",
        "version": "0.1.0",
        "channel": "developer-preview",
        "commit": "b".repeat(40),
        "validated_target": "aarch64-apple-darwin",
        "artifacts": {
            "crate": {"path": "iicp-management-core-0.1.0.crate", "sha256": digest},
            "offline_bundle": {"path": "iicp-management-core-0.1.0-offline.tar.gz", "sha256": format!("sha256:{}", "c".repeat(64))}
        },
        "contracts": [{"path": "contracts/management-contract-v1.schema.json", "sha256": format!("sha256:{}", "d".repeat(64))}],
        "binaries": ["iicp-management", "iicp-management-controller", "iicp-management-conformance"],
        "known_limitations": ["no publication or deployment implied"],
        "authorizes_publication": false,
        "authorizes_deployment": false
    });
    assert!(validator.is_valid(&manifest));

    let mut unsafe_manifest = manifest;
    unsafe_manifest["authorizes_deployment"] = json!(true);
    assert!(!validator.is_valid(&unsafe_manifest));
}

#[test]
fn generated_release_manifest_matches_schema_and_artifact_version() {
    let Some(path) = env::var_os("IICP_RELEASE_MANIFEST") else {
        return;
    };
    let schema: Value = serde_json::from_str(
        &fs::read_to_string("contracts/management-release-manifest-v1.schema.json").unwrap(),
    )
    .unwrap();
    let manifest: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let validator = validator_for(&schema).unwrap();
    let errors = validator
        .iter_errors(&manifest)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "generated manifest failed schema validation: {errors:?}"
    );

    let version = manifest["version"].as_str().unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert!(artifact_versions_match(&manifest));
    assert_eq!(manifest["authorizes_publication"], false);
    assert_eq!(manifest["authorizes_deployment"], false);
}

#[test]
fn release_manifest_rejects_malformed_versions_and_artifact_drift() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string("contracts/management-release-manifest-v1.schema.json").unwrap(),
    )
    .unwrap();
    let validator = validator_for(&schema).unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let base = json!({
        "schema": "iicp.management-release-manifest.v1",
        "product": "iicp-management-core",
        "version": env!("CARGO_PKG_VERSION"),
        "channel": "developer-preview",
        "commit": "b".repeat(40),
        "validated_target": "test-host",
        "artifacts": {
            "crate": {"path": format!("iicp-management-core-{}.crate", env!("CARGO_PKG_VERSION")), "sha256": digest},
            "offline_bundle": {"path": format!("iicp-management-core-{}-offline.tar.gz", env!("CARGO_PKG_VERSION")), "sha256": format!("sha256:{}", "c".repeat(64))}
        },
        "contracts": [{"path": "contracts/management-contract-v1.schema.json", "sha256": format!("sha256:{}", "d".repeat(64))}],
        "binaries": ["iicp-management", "iicp-management-controller", "iicp-management-conformance"],
        "known_limitations": ["no deployment implied"],
        "authorizes_publication": false,
        "authorizes_deployment": false
    });
    assert!(validator.is_valid(&base));
    assert!(artifact_versions_match(&base));

    let mut malformed = base.clone();
    malformed["version"] = json!("latest");
    assert!(!validator.is_valid(&malformed));

    let mut drifted = base;
    drifted["artifacts"]["crate"]["path"] = json!("iicp-management-core-0.0.0.crate");
    assert!(!artifact_versions_match(&drifted));
}
