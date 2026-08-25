#!/usr/bin/env python3
"""Standard-library checker for candidate eligibility classification."""
import json
import sys
from pathlib import Path


def classify(decision, compatibility, expired):
    if expired:
        return {"eligibility": "unresolved", "reason_code": "IICP-MGMT-CANDIDATE-EVIDENCE-STALE"}
    if decision == "deny":
        return {"eligibility": "ineligible", "reason_code": None}
    if decision == "indeterminate":
        return {"eligibility": "unresolved", "reason_code": None}
    if decision != "allow":
        raise ValueError("unknown decision")
    if compatibility == "compatible":
        return {"eligibility": "eligible", "reason_code": None}
    if compatibility == "incompatible":
        return {"eligibility": "ineligible", "reason_code": "IICP-MGMT-CANDIDATE-INCOMPATIBLE"}
    if compatibility == "unknown":
        return {"eligibility": "unresolved", "reason_code": "IICP-MGMT-CANDIDATE-COMPATIBILITY-UNKNOWN"}
    raise ValueError("unknown compatibility")


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/resolution-inspection-conformance-v1.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for case in data["cases"]:
        try:
            actual = classify(case["decision"], case["compatibility"], case["evidence_expired"])
        except (KeyError, ValueError, TypeError) as error:
            actual = {"error": str(error)}
        results.append({"id": case["id"], "passed": actual == case["expected"], "actual": actual})
    report = {
        "schema_version": "1",
        "runner": "iicp-management-resolution-inspection-python/1",
        "evidence_class": "project-verified",
        "passed": sum(result["passed"] for result in results),
        "failed": sum(not result["passed"] for result in results),
        "cases": results,
    }
    print(json.dumps(report, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
