#!/usr/bin/env python3
"""Standard-library checker for bootstrap-workflow-v1 portable fixtures."""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def valid(value: dict, now: int) -> bool:
    try:
        assessment = value["assessment"]
        doctor = value["doctor"]
        sources = value["source_digests"]
        observed = sorted(
            {
                item["evidence_digest"]
                for item in assessment["observations"]
                if "evidence_digest" in item
            }
        )
        ready = assessment["readiness"] == "ready_for_proposal"
        proposal = value.get("proposal")
        return all(
            [
                value["schema_version"] == "iicp.management-bootstrap-workflow.v1",
                value["authorizes_mutation"] is False,
                value["activated"] is False,
                0 < len(sources) <= 1024,
                sources == sorted(set(sources)) == observed,
                all(DIGEST.fullmatch(item) for item in sources),
                assessment["authorizes_mutation"] is False,
                assessment["observed_at"] <= now <= assessment["expires_at"],
                doctor["schema_version"] == "iicp.management-doctor-report.v1",
                doctor["assessment_id"] == assessment["assessment_id"],
                doctor["authorizes_mutation"] is False,
                bool(doctor["checks"]),
                (ready and proposal is not None) or (not ready and proposal is None),
                proposal is None
                or proposal["bundle_id"] == f"bootstrap:{assessment['assessment_id']}",
            ]
        )
    except (KeyError, TypeError):
        return False


def materialize(case: dict, known: dict[str, dict]) -> dict:
    if "workflow" in case:
        return copy.deepcopy(case["workflow"])
    value = copy.deepcopy(known[case["mutate_from"]])
    mutation = case["mutation"]
    if mutation == "remove_proposal":
        value.pop("proposal", None)
    elif mutation == "replace_source_digest":
        value["source_digests"][0] = "sha256:" + "f" * 64
    elif mutation == "set_authorizes_mutation":
        value["authorizes_mutation"] = True
    else:
        raise ValueError(f"unknown mutation: {mutation}")
    return value


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(
        "fixtures/bootstrap-workflow-conformance-v1.json"
    )
    fixture = json.loads(path.read_text(encoding="utf-8"))
    known: dict[str, dict] = {}
    results = []
    for case in fixture["cases"]:
        value = materialize(case, known)
        known[case["id"]] = value
        actual = "accept" if valid(value, fixture["evaluated_at"]) else "reject"
        results.append({"id": case["id"], "expected": case["expected"], "actual": actual})
    passed = all(item["actual"] == item["expected"] for item in results)
    print(json.dumps({"passed": passed, "results": results}, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
