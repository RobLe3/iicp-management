#!/usr/bin/env python3
"""Offline #168 development vectors. No evaluator, signature verifier, or apply gate."""
import hashlib
import json
import re
from pathlib import Path

PACK = "iicp.management.external-evaluator.development-cases.v1"
PROFILE = "iicp.management.external-evaluator.development.v1"
PROFILE_CASE = "MP1-COMPATIBLE"
SOURCE_ISSUE = "https://github.com/RobLe3/iicp-management/issues/168"
MAX_TICK = 2**53 - 1
MAX_DOCUMENT_BYTES = 128 * 1024
BINDING_FIELDS = {
    "request_id", "action", "target", "audience", "domain", "policy_generation",
    "required_parameters",
}
RESULT_FIELDS = {
    "schema", "evaluator", "version", "binding", "decision", "issued_at",
    "expires_at", "reasons", "evidence", "obligations", "extensions",
    "authorizes_mutation", "request_digest",
}


def unique_members(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key}")
        value[key] = child
    return value


def invalid_constant(value):
    raise ValueError(f"non-JSON constant: {value}")


def load_fixture(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError("fixture document out of bounds")
    return json.loads(raw, object_pairs_hook=unique_members, parse_constant=invalid_constant)


def bounded_id(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value) is not None


def identifiers(values, *, nonempty=False):
    return (type(values) is list and (not nonempty or bool(values))
            and len(values) <= 16 and all(bounded_id(value) for value in values)
            and len(set(values)) == len(values))


def fixture_binding(value, config):
    return (type(value) is dict and set(value) == BINDING_FIELDS
            and all(bounded_id(value[key]) for key in BINDING_FIELDS - {"required_parameters", "policy_generation"})
            and tick(value["policy_generation"]) and value["policy_generation"] > 0
            and identifiers(value["required_parameters"])
            and set(value["required_parameters"]) <= set(config["known_parameters"]))


def tick(value):
    return type(value) is int and 0 <= value <= MAX_TICK


def validate_pack(pack):
    required = {"schema", "status", "source_issue", "fixture_context", "request",
                "checked_at", "result", "cases"}
    if (type(pack) is not dict or set(pack) != required or pack["schema"] != PACK
            or pack["status"] != "experimental-non-activating" or pack["source_issue"] != SOURCE_ISSUE):
        raise ValueError("unsupported experimental fixture")

    config = pack["fixture_context"]
    required = {"evaluator", "version", "known_parameters", "known_resolvers",
                "noncritical_extensions", "max_validity"}
    if (type(config) is not dict or set(config) != required
            or not bounded_id(config["evaluator"]) or not bounded_id(config["version"])
            or any(not identifiers(config[key], nonempty=True)
                   for key in ("known_parameters", "known_resolvers", "noncritical_extensions"))
            or not tick(config["max_validity"]) or not 1 <= config["max_validity"] <= 3600):
        raise ValueError("invalid fixture context")

    if (not fixture_binding(pack["request"], config) or not tick(pack["checked_at"])
            or type(pack["result"]) is not dict
            or classify(pack["result"], pack["request"], "allow", pack["checked_at"], config)["state"] != "eligible"):
        raise ValueError("invalid fixture request, clock or baseline result")

    cases = pack["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= 64:
        raise ValueError("invalid fixture case list")
    required = {"id", "derivation", "expected"}
    optional = {"checked_at", "local_policy", "result_overrides"}
    expected_keys = {"state", "reason", "authorizes_mutation", "preserves_evidence"}
    ids = set()
    for case in cases:
        if (type(case) is not dict or not required <= set(case) <= required | optional
                or not bounded_id(case["id"]) or case["id"] in ids
                or type(case["derivation"]) is not str or not case["derivation"].strip()
                or len(case["derivation"]) > 512
                or not tick(case.get("checked_at", pack["checked_at"]))
                or case.get("local_policy", "allow") not in ("allow", "deny")):
            raise ValueError("invalid or duplicate vector")
        ids.add(case["id"])
        overrides = case.get("result_overrides", {})
        if type(overrides) is not dict or not set(overrides) <= RESULT_FIELDS:
            raise ValueError("invalid result override envelope")
        expected = case["expected"]
        if (type(expected) is not dict or not expected_keys <= set(expected) <= expected_keys | {"evidence"}
                or expected["state"] not in ("eligible", "denied", "deferred", "rejected")
                or not bounded_id(expected["reason"]) or expected["authorizes_mutation"] is not False
                or type(expected["preserves_evidence"]) is not bool
                or expected["preserves_evidence"] is not (expected["state"] != "rejected")
                or ("evidence" in expected and
                    (not expected["preserves_evidence"] or type(expected["evidence"]) is not dict))):
            raise ValueError("invalid expected outcome envelope")


def fixture_digest(value):
    # Fixture values use only ASCII object keys/strings and small integers.
    # This is a local reproducibility checksum, not a wire integrity convention.
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def classify(result, request, local_policy, now, config):
    """Return a development classification. Even ELIGIBLE is not local-apply authorization."""
    def outcome(state, reason, evidence=None):
        return {"state": state, "reason": reason, "authorizes_mutation": False,
                "evidence": evidence}

    if set(result) != RESULT_FIELDS or result["schema"] != PROFILE or result["authorizes_mutation"] is not False:
        return outcome("rejected", "invalid_result")
    if result["evaluator"] != config["evaluator"] or result["version"] != config["version"]:
        return outcome("rejected", "unsupported_evaluator")
    bound = result["binding"]
    if type(bound) is not dict or set(bound) != BINDING_FIELDS:
        return outcome("rejected", "invalid_binding")
    required = bound["required_parameters"]
    if not identifiers(required) or any(item not in config["known_parameters"] for item in required):
        return outcome("rejected", "unsupported_required_parameter")
    if (type(bound["policy_generation"]) is not int
            or any(not bounded_id(bound[key]) for key in BINDING_FIELDS - {"required_parameters", "policy_generation"})
            or bound != request or result["request_digest"] != fixture_digest(request)):
        return outcome("rejected", "binding_mismatch")

    issued, expiry = result["issued_at"], result["expires_at"]
    if (type(issued) is not int or type(expiry) is not int
            or not 0 <= issued <= now < expiry <= MAX_TICK
            or expiry - issued > config["max_validity"]):
        return outcome("rejected", "stale_or_expired")
    if (not identifiers(result["reasons"], nonempty=True)
            or not identifiers(result["evidence"], nonempty=True)
            or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in result["evidence"])):
        return outcome("rejected", "invalid_evidence")

    extensions = result["extensions"]
    if (type(extensions) is not dict
            or any(key not in config["noncritical_extensions"] or not bounded_id(value)
                   for key, value in extensions.items())):
        return outcome("rejected", "undeclared_extension")

    decision = result["decision"]
    obligations = result["obligations"]
    if (decision not in ("allow", "deny", "allow_unresolved") or type(obligations) is not list
            or len(obligations) > 16 or (decision != "allow_unresolved" and obligations)):
        return outcome("rejected", "invalid_result")
    if decision == "allow_unresolved":
        if not obligations or any(
            type(item) is not dict or set(item) != {"id", "resolver", "failure"}
            or not bounded_id(item["id"]) or item["resolver"] not in config["known_resolvers"]
            or item["failure"] != "deny" for item in obligations
        ) or len({item["id"] for item in obligations}) != len(obligations):
            return outcome("rejected", "unbound_resolution")
    evidence = {
        "result_digest": fixture_digest(result), "request_id": request["request_id"],
        "request_digest": result["request_digest"],
        "evaluator": result["evaluator"], "version": result["version"],
        "policy_generation": bound["policy_generation"], "issued_at": issued,
        "expires_at": expiry, "checked_at": now, "decision": decision,
        "reasons": result["reasons"], "references": result["evidence"],
    }
    if local_policy != "allow" or decision == "deny":
        return outcome("denied", "deny_precedence", evidence)
    if decision == "allow_unresolved":
        return outcome("deferred", "await_named_resolution", evidence)
    return outcome("eligible", "local_and_external_allow", evidence)


def main():
    repo = Path(__file__).resolve().parents[1]
    # Reuse the already accepted management profile input without changing it.
    from run_management_profile_conformance import intersect, valid_profile

    profile_pack = load_fixture(repo / "fixtures/management-profile-conformance-v1.json")
    compatibility = next(case for case in profile_pack["cases"] if case["id"] == PROFILE_CASE)
    offer = compatibility["profile"]
    requirement = compatibility["requirement"]
    if not valid_profile(offer, compatibility["now"]) or intersect(offer, requirement):
        raise ValueError("fixture's management profile compatibility prerequisite failed")

    pack = load_fixture(repo / "tests/fixtures/management-external-evaluator-development-v1.json")
    validate_pack(pack)
    request = pack["request"]
    if (request["audience"] != offer["controller_id"]
            or request["domain"] != requirement["administrative_domain"]
            or request["action"] not in requirement["operations"]):
        raise ValueError("fixture request does not match compatibility context")
    config = pack["fixture_context"]
    records = []
    for case in pack["cases"]:
        result = {**pack["result"], **case.get("result_overrides", {})}
        actual = classify(result, pack["request"], case.get("local_policy", "allow"),
                          case.get("checked_at", pack["checked_at"]), config)
        expected = case["expected"]
        # Every vector independently requires non-mutation, regardless of verdict.
        passed = (all(actual[key] == expected[key] for key in ("state", "reason", "authorizes_mutation"))
                  and (actual["evidence"] is not None) == expected["preserves_evidence"]
                  and ("evidence" not in expected or actual["evidence"] == expected["evidence"])
                  and bool(case["derivation"]))
        records.append({"id": case["id"], "passed": passed, "actual": actual})
    failed = sum(not result["passed"] for result in records)
    print(json.dumps({"schema": PACK, "evidence_class": "development-only",
                      "passed": len(records) - failed, "failed": failed, "cases": records},
                     sort_keys=True))
    return int(failed != 0)


if __name__ == "__main__":
    raise SystemExit(main())
