#!/usr/bin/env python3
import json, sys
from pathlib import Path

REQUIRED_PROFILE={"schema_version","controller_id","administrative_domains","api_versions","schema_ids","canonicalization","signature_algorithms","operations","resource_kinds","policy_evaluators","limits","evidence","conformance","validity","extensions","authorizes_mutation"}

def valid_id(value): return isinstance(value,str) and 0<len(value)<=256 and not any(c.isspace() for c in value)
def valid_set(values, required=False): return isinstance(values,list) and (not required or bool(values)) and len(values)<=1024 and len(set(values))==len(values) and all(valid_id(v) for v in values)
def valid_profile(p, now):
    if set(p)!=REQUIRED_PROFILE or p["schema_version"]!="iicp.management-profile.v1" or p["authorizes_mutation"] is not False or not valid_id(p["controller_id"]): return False
    v=p["validity"]
    if set(v)!={"issued_at","not_before","expires_at","generation"} or not (v["issued_at"]<=v["not_before"]<=now<=v["expires_at"]) or v["generation"]<1: return False
    for key in ("administrative_domains","api_versions","schema_ids","canonicalization","signature_algorithms","operations","policy_evaluators"):
        if not valid_set(p[key],True): return False
    for key in ("resource_kinds","evidence","conformance"):
        if not valid_set(p[key]): return False
    return bool(p["limits"]) and all(valid_id(k) and isinstance(v,int) and v>0 for k,v in p["limits"].items())

def intersect(p,r):
    reasons=[]
    if r.get("controller_id") and r["controller_id"]!=p["controller_id"]: reasons.append("PROFILE_CONTROLLER_MISMATCH")
    if r.get("administrative_domain") and r["administrative_domain"] not in p["administrative_domains"]: reasons.append("PROFILE_DOMAIN_UNSUPPORTED")
    for field,label in (("api_versions","API"),("schema_ids","SCHEMA"),("canonicalization","CANONICALIZATION"),("signature_algorithms","SIGNATURE"),("operations","OPERATION"),("resource_kinds","RESOURCE_KIND"),("policy_evaluators","POLICY_EVALUATOR")):
        reasons += [f"PROFILE_REQUIRED_{label}_UNSUPPORTED:{v}" for v in r.get(field,[]) if v not in p[field]]
    offered={x["id"] for x in p["extensions"]}
    reasons += [f"PROFILE_REQUIRED_EXTENSION_UNSUPPORTED:{x['id']}" for x in r.get("extensions",[]) if x["id"] not in offered and x["class"] in {"REQUIRED_UNDERSTOOD","REQUIRED_SECURITY_CRITICAL"}]
    return sorted(set(reasons))

def main():
    path=Path(sys.argv[1] if len(sys.argv)>1 else 'fixtures/management-profile-conformance-v1.json')
    data=json.loads(path.read_text()); results=[]
    for case in data["cases"]:
        if not valid_profile(case["profile"],case["now"]): result,reasons="reject",["MANAGEMENT_PROFILE_INVALID"]
        else:
            reasons=intersect(case["profile"],case["requirement"]); result="incompatible" if reasons else "compatible"
        passed=result==case["expected"]["result"] and reasons==case["expected"]["reasons"]
        results.append({"id":case["id"],"actual":result,"reasons":reasons,"passed":passed})
    report={"schema_version":"1","runner":"iicp-management-profile-python/1","evidence_class":"project-verified","passed":sum(x["passed"] for x in results),"failed":sum(not x["passed"] for x in results),"cases":results}
    print(json.dumps(report,sort_keys=True)); return 1 if report["failed"] else 0
if __name__=='__main__': raise SystemExit(main())
