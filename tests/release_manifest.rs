use jsonschema::validator_for;
use serde_json::{json, Value};
use std::fs;

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
