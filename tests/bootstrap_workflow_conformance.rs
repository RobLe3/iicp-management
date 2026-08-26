use iicp_management_core::bootstrap::{validate_workflow, BootstrapWorkflowV1};
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn portable_bootstrap_workflow_cases_match_the_rust_validator() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../fixtures/bootstrap-workflow-conformance-v1.json"
    ))
    .unwrap();
    let now = fixture["evaluated_at"].as_u64().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    let mut materialized = BTreeMap::<String, Value>::new();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let value = if let Some(workflow) = case.get("workflow") {
            workflow.clone()
        } else {
            let source = case["mutate_from"].as_str().unwrap();
            let mut value = materialized.get(source).unwrap().clone();
            match case["mutation"].as_str().unwrap() {
                "remove_proposal" => value
                    .as_object_mut()
                    .unwrap()
                    .remove("proposal")
                    .map(|_| ()),
                "replace_source_digest" => {
                    value["source_digests"][0] =
                        Value::String(format!("sha256:{}", "f".repeat(64)));
                    Some(())
                }
                "set_authorizes_mutation" => {
                    value["authorizes_mutation"] = Value::Bool(true);
                    Some(())
                }
                _ => panic!("unknown mutation"),
            };
            value
        };
        materialized.insert(id.into(), value.clone());
        let outcome = serde_json::from_value::<BootstrapWorkflowV1>(value)
            .map_err(|error| error.to_string())
            .and_then(|value| validate_workflow(&value, now));
        assert_eq!(
            outcome.is_ok(),
            case["expected"] == "accept",
            "case {id}: {outcome:?}"
        );
    }
}
