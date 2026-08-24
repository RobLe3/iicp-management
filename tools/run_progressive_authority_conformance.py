#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED = {"REQUIRED_UNDERSTOOD", "REQUIRED_SECURITY_CRITICAL"}


def reject(reason):
    return {"result": "reject", "reason": reason}


def validate(value):
    if value["schema_version"] != "1":
        return reject("PROGRESSIVE_AUTHORITY_UNSUPPORTED_VERSION")
    if any(not value[name].strip() for name in ("evidence_id", "application_id", "intent")):
        return reject("PROGRESSIVE_AUTHORITY_EMPTY_IDENTIFIER")
    digests = [value["fact_snapshot_digest"], value["plan_digest"], value["authorization_evidence_digest"]]
    if any(item is not None and not DIGEST.fullmatch(item) for item in digests):
        return reject("PROGRESSIVE_AUTHORITY_INVALID_DIGEST")
    for extension in value["extensions"]:
        if extension["class"] in REQUIRED:
            return reject(f"PROGRESSIVE_AUTHORITY_UNSUPPORTED_REQUIRED_EXTENSION:{extension['id']}")

    mode = value["mode"]
    if mode == "observe":
        valid = value["actual_decision"] is not None and value["proposed_decision"] is None
        valid &= value["plan_digest"] is None and value["authorization_evidence_digest"] is None
        valid &= not value["may_request_apply"]
        return {"result": "accept"} if valid else reject("PROGRESSIVE_AUTHORITY_INVALID_MODE_EVIDENCE")
    if mode == "recommend":
        valid = value["actual_decision"] is not None and value["proposed_decision"] is not None
        valid &= value["plan_digest"] is None and value["authorization_evidence_digest"] is None
        valid &= not value["may_request_apply"]
        return {"result": "accept"} if valid else reject("PROGRESSIVE_AUTHORITY_INVALID_MODE_EVIDENCE")
    if mode in {"confirm", "automatic_within_policy"}:
        authorized = value["proposed_decision"] is not None and value["plan_digest"] is not None
        authorized &= value["authorization_evidence_digest"] is not None and value["may_request_apply"]
        if not authorized:
            return reject("PROGRESSIVE_AUTHORITY_APPLY_NOT_AUTHORIZED")
        if value["policy_boundary"] != "satisfied":
            return reject("PROGRESSIVE_AUTHORITY_POLICY_BOUNDARY_NOT_SATISFIED")
        return {"result": "accept"}
    return reject("PROGRESSIVE_AUTHORITY_INVALID_MODE_EVIDENCE")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text())
    results = []
    for case in fixture["cases"]:
        actual = validate(case["input"])
        if (
            actual == {"result": "accept"}
            and case.get("operation") == "validate_generation"
            and case["input"]["policy_generation"] != case["current_policy_generation"]
        ):
            actual = reject("PROGRESSIVE_AUTHORITY_STALE_POLICY_GENERATION")
        results.append({"id": case["id"], "passed": actual == case["expected"], "actual": actual})
    report = {
        "schema": "iicp.management-progressive-authority.result.v1",
        "evidence_class": "project-verified",
        "fixture_version": fixture["version"],
        "passed": sum(result["passed"] for result in results),
        "failed": sum(not result["passed"] for result in results),
        "results": results,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
