#!/usr/bin/env python3
"""Portable EM-1 fixture checker; intentionally independent of the Rust crate."""
import argparse, hashlib, json, subprocess
from pathlib import Path

RUNNER = "iicp-management-portable/1.0.0"

def digest(value):
    encoded=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return "sha256:"+hashlib.sha256(encoded).hexdigest()

def evaluate(case):
    op, data = case["operation"], case["input"]
    if op == "digest": return digest(data)
    if op == "plan":
        bundle=data["bundle"].copy(); bundle["resources"]=sorted(bundle["resources"],key=lambda x:x["resource_id"]); bundle["extensions"]=sorted(bundle.get("extensions",[]),key=lambda x:(x["class"],x["id"]))
        target=data["accepted"]["generation"]+1; operations=[]
        for index,resource in enumerate(bundle["resources"],1):
            before=data["accepted"].get("resource_digests",{}).get(resource["resource_id"],"absent")
            operations.append({"operation_id":f"op-{index:04d}","resource_id":resource["resource_id"],"action":"create" if before=="absent" else "update","before_digest":before,"after_digest":digest(resource["desired"]),"expected_generation":data["accepted"]["generation"],"target_generation":target,"idempotency_key":f"{bundle['bundle_id']}:{resource['resource_id']}"})
        return {"schema_version":"1","planner_version":"iicp-management-planner/0.1.0","bundle_id":bundle["bundle_id"],"bundle_digest":digest(bundle),"expected_generation":data["accepted"]["generation"],"target_generation":target,"operations":operations}
    if op == "approval":
        a,p=data["approval"],data["plan"]
        if a["audience"] != p["audience"]: return "AUTHZ_WRONG_AUDIENCE"
        if any(a[k] != p[k] for k in ("generation","bundle_digest","plan_digest")): return "PLAN_APPROVAL_DIGEST_MISMATCH"
        return "authorized"
    if op == "receipt":
        observed=[x["resource_id"] for x in data["observations"]]
        if sorted(observed) != sorted(data["expected_resources"]) or len(set(observed)) != len(observed): return "RECEIPT_BINDING_MISMATCH"
        states=[x["state"] for x in data["observations"]]
        actual="converged" if states and all(x=="converged" for x in states) else "failed" if not states or all(x=="failed" for x in states) else "partially_converged"
        return "verified" if actual == data["claimed"] else "RECEIPT_EFFECTIVE_STATE_MISMATCH"
    if op == "extension":
        return "PROFILE_UNSUPPORTED_REQUIRED" if not data["supported"] and data["class"] in {"REQUIRED_UNDERSTOOD","REQUIRED_SECURITY_CRITICAL"} else "continue"
    raise ValueError(f"unknown operation: {op}")

def main():
    p=argparse.ArgumentParser(); p.add_argument("fixture",type=Path); p.add_argument("--output",type=Path); a=p.parse_args()
    fixture=json.loads(a.fixture.read_text()); seen=set(); results=[]
    for case in fixture["cases"]:
        if case["id"] in seen: raise SystemExit(f"duplicate case id: {case['id']}")
        seen.add(case["id"]); actual=evaluate(case); results.append({"id":case["id"],"passed":actual==case["expected"],"actual":actual})
    try: commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
    except Exception: commit="unknown"
    report={"schema_version":"1","fixture_version":fixture["fixture_version"],"runner":RUNNER,"evidence_class":"project-verified","repository":"https://github.com/RobLe3/iicp-management","commit":commit,"passed":sum(x["passed"] for x in results),"failed":sum(not x["passed"] for x in results),"cases":results}
    output=json.dumps(report,indent=2)+"\n"
    if a.output: a.output.write_text(output)
    else: print(output,end="")
    return 0 if report["failed"]==0 else 1
if __name__ == "__main__": raise SystemExit(main())
