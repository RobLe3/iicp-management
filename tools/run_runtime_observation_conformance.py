#!/usr/bin/env python3
"""Standard-library checker for the runtime-observation effective-state rules."""
import json
import sys
from pathlib import Path


def classify(stale, liveness, readiness):
    if stale:
        return {"effective_state": "unknown", "reason_code": "IICP-MGMT-RUNTIME-EVIDENCE-STALE"}
    if liveness == "not_live":
        return {"effective_state": "not_ready", "reason_code": None}
    if liveness == "indeterminate":
        return {"effective_state": "unknown", "reason_code": None}
    if liveness not in {"live", "starting"} or readiness not in {"ready", "degraded", "not_ready"}:
        raise ValueError("unknown runtime state")
    return {"effective_state": readiness, "reason_code": None}


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/runtime-observation-conformance-v1.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for case in data["cases"]:
        try:
            actual = classify(case["stale"], case["liveness"], case["readiness"])
        except (KeyError, TypeError, ValueError) as error:
            actual = {"error": str(error)}
        results.append({"id": case["id"], "passed": actual == case["expected"], "actual": actual})
    report = {
        "schema_version": "1",
        "runner": "iicp-management-runtime-observation-python/1",
        "evidence_class": "project-verified",
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "cases": results,
    }
    print(json.dumps(report, sort_keys=True))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
