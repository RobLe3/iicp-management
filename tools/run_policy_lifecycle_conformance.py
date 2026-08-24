#!/usr/bin/env python3
"""Standard-library reference checker for policy lifecycle v1 fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def reject(reason: str) -> dict[str, object]:
    return {"result": "reject", "reason": reason}


def validate_revision(value: dict[str, object]) -> dict[str, object]:
    if value.get("schema_version") != "1":
        return reject("POLICY_UNSUPPORTED_VERSION")
    required = ("policy_id", "revision_id", "authority", "scope")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
        return reject("POLICY_EMPTY_IDENTIFIER")
    start, end = value.get("valid_from"), value.get("valid_until")
    if start is not None and end is not None and end <= start:
        return reject("POLICY_INVALID_VALIDITY")
    return {"result": "accept"}


def validate_binding(value: dict[str, object]) -> dict[str, object]:
    if value.get("schema_version") != "1":
        return reject("POLICY_UNSUPPORTED_VERSION")
    orders: set[int] = set()
    for reference in [*value.get("policies", []), *value.get("policy_sets", [])]:
        order = reference.get("order")
        if order in orders:
            return reject("POLICY_DUPLICATE_MEMBER")
        orders.add(order)
    return {"result": "accept"}


def evaluate(policy: dict[str, object], facts: dict[str, object]) -> str:
    if "eq" in policy:
        key, expected = policy["eq"]
        return "allow" if facts.get(key) == expected else "deny"
    if "contains" in policy:
        key, expected = policy["contains"]
        actual = facts.get(key)
        if not isinstance(actual, list):
            return "indeterminate"
        return "allow" if expected in actual else "deny"
    return "indeterminate"


def compose(value: dict[str, object]) -> dict[str, object]:
    sources = sorted(
        value["sources"],
        key=lambda item: (-item["authority_rank"], item["order"], item["policy_id"], item["revision_id"]),
    )
    decisions = [(source, evaluate(source["policy"], value["facts"])) for source in sources]
    if any(decision == "deny" for _, decision in decisions):
        result = "deny"
    elif any(source["mandatory"] and decision == "indeterminate" for source, decision in decisions):
        result = "indeterminate"
    elif decisions and all(decision == "allow" for _, decision in decisions):
        result = "allow"
    else:
        result = "indeterminate"
    return {"decision": result, "ordered_policy_ids": [source["policy_id"] for source in sources]}


def run(case: dict[str, object]) -> dict[str, object]:
    operation, value = case["operation"], case["input"]
    if operation == "validate_revision":
        return validate_revision(value)
    if operation == "validate_binding":
        return validate_binding(value)
    if operation == "compose":
        return compose(value)
    if operation == "validate_activation_generation":
        if value["expected_generation"] != value["current_generation"]:
            return reject("POLICY_STALE_GENERATION")
        if value["target_generation"] != value["current_generation"] + 1:
            return reject("POLICY_ACTIVATION_INVALID")
        return {"result": "accept"}
    if operation == "simulate_decision_change":
        current, proposed = value["current"], value["proposed"]
        return {
            "decision_changed": current != proposed,
            "newly_allowed": current != "allow" and proposed == "allow",
            "newly_denied": current != "deny" and proposed == "deny",
        }
    raise ValueError(f"unsupported operation: {operation}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text())
    results = []
    failures = 0
    for case in fixture["cases"]:
        actual = run(case)
        passed = actual == case["expected"]
        failures += not passed
        results.append({"id": case["id"], "passed": passed, "actual": actual})
    report = {
        "schema": "iicp.management-policy-lifecycle.result.v1",
        "evidence_class": "project-verified",
        "fixture_version": fixture["version"],
        "passed": len(results) - failures,
        "failed": failures,
        "results": results,
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        sys.stdout.write(encoded)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
