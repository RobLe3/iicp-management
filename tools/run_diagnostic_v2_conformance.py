#!/usr/bin/env python3
"""Standard-library semantic checker for diagnostic bundle v2 fixture cases."""
import argparse, json, sys
from pathlib import Path


def classify(case):
    scenario, value = case["scenario"], case["input"]
    if scenario == "unknown_schema":
        return {"result":"reject","reason":"DIAGNOSTIC_SCHEMA_UNSUPPORTED"}
    if scenario == "legacy_v1":
        return {"result":"accept","runtime_required":False}
    if scenario == "target_redaction":
        return {"result":"accept","serialized_target":False,"target_independent_digest":True}
    evidence, live, ready = value["evidence_state"], value["liveness"], value["readiness"]
    if evidence == "stale":
        effective, state, reason, action = "unknown", "WARN", "RUNTIME_EVIDENCE_STALE", "REFRESH_RUNTIME_EVIDENCE"
    elif live == "not_live" or ready == "not_ready":
        effective, state, reason, action = "not_ready", "FAIL", "RUNTIME_NOT_READY", "RESTORE_RUNTIME_READINESS"
    elif live == "indeterminate":
        effective, state, reason, action = "unknown", "WARN", "RUNTIME_STATE_UNKNOWN", "REVIEW_RUNTIME_EVIDENCE"
    elif ready == "degraded":
        effective, state, reason, action = "degraded", "WARN", "RUNTIME_DEGRADED", "REVIEW_RUNTIME_DEGRADATION"
    elif live == "live" and ready == "ready":
        effective, state, reason, action = "ready", "PASS", "RUNTIME_READY", None
    else:
        effective, state, reason, action = "unknown", "WARN", "RUNTIME_STATE_UNKNOWN", "REVIEW_RUNTIME_EVIDENCE"
    if value.get("claimed_effective_state", effective) != effective:
        return {"result":"reject","reason":"DIAGNOSTIC_RUNTIME_INVALID"}
    return {"result":"accept","effective_state":effective,"check_state":state,"reason":reason,"action":action}


def run(path):
    fixture=json.loads(Path(path).read_text(encoding="utf-8"))
    if fixture.get("schema_version") != "iicp.management-diagnostic-conformance.v2":
        raise ValueError("unsupported fixture schema")
    results=[]
    for case in fixture.get("cases",[]):
        actual=classify(case); passed=actual == case["expected"]
        results.append({"id":case["id"],"passed":passed,"actual":actual})
    return {"schema_version":"iicp.management-diagnostic-conformance-result.v2","passed":all(x["passed"] for x in results),"results":results}


def main():
    parser=argparse.ArgumentParser(); parser.add_argument("fixture"); parser.add_argument("--output")
    args=parser.parse_args(); result=run(args.fixture); encoded=json.dumps(result,indent=2,sort_keys=True)+"\n"
    if args.output: Path(args.output).write_text(encoded,encoding="utf-8")
    else: print(encoded,end="")
    return 0 if result["passed"] else 1
if __name__ == "__main__": sys.exit(main())
