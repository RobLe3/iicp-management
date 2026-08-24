#!/usr/bin/env python3
import json, re, sys
from pathlib import Path

DIGEST=re.compile(r'^sha256:[0-9a-fA-F]{64}$')

def valid(v, now, skew):
    required={"schema_version","evidence_class","evidence_source","authorizes_mutation","observed_at","expires_at","entries","extensions"}
    if set(v)!=required or v["schema_version"]!="1" or v["evidence_class"]!="adapter_host_observation" or v["evidence_source"]!="domain_local_adapter_host" or v["authorizes_mutation"] is not False:
        return False
    if v["observed_at"]>now+skew or v["expires_at"]<v["observed_at"] or now>v["expires_at"] or len(v["entries"])>1024:
        return False
    seen=set()
    for x in v["extensions"]:
        if set(x)!={"id","class"} or (x["class"] in {"REQUIRED_UNDERSTOOD","REQUIRED_SECURITY_CRITICAL"}): return False
    for e in v["entries"]:
        allowed={"target_id","registered_capability","advertised_capabilities","descriptor_digest","observation_digest","observed_generation","convergence_state","reason_code"}
        if not set(e)<=allowed or not {"target_id","registered_capability","advertised_capabilities","descriptor_digest","reason_code"}<=set(e): return False
        ident=(e["target_id"],e["registered_capability"])
        caps=e["advertised_capabilities"]
        if ident in seen or not e["target_id"] or not e["registered_capability"] or not e["reason_code"] or not DIGEST.fullmatch(e["descriptor_digest"]): return False
        if e.get("observation_digest") is not None and not DIGEST.fullmatch(e["observation_digest"]): return False
        if caps != sorted(set(caps)) or e["registered_capability"] not in caps: return False
        seen.add(ident)
    return True

def main():
    path=Path(sys.argv[1] if len(sys.argv)>1 else 'fixtures/adapter-inspection-conformance-v1.json')
    data=json.loads(path.read_text()); results=[]
    for case in data["cases"]:
        actual="accept" if valid(case["input"],data["now"],data["clock_skew"]) else "reject"
        results.append({"id":case["id"],"passed":actual==case["expected"],"actual":actual})
    report={"schema_version":"1","runner":"iicp-management-adapter-inspection-python/1","evidence_class":"project-verified","passed":sum(r["passed"] for r in results),"failed":sum(not r["passed"] for r in results),"cases":results}
    print(json.dumps(report,sort_keys=True))
    return 1 if report["failed"] else 0
if __name__=='__main__': raise SystemExit(main())
