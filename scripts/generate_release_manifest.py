#!/usr/bin/env python3
"""Generate an integrity-bound, non-authorizing management preview manifest."""
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, tomllib
from pathlib import Path

HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")

def sha256(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            digest.update(chunk)
    return "sha256:"+digest.hexdigest()

def version(manifest: Path) -> str:
    value=tomllib.loads(manifest.read_text())["package"]["version"]
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?", value):
        raise ValueError("RELEASE_VERSION_INVALID")
    return value

def build(root: Path, crate: Path, offline: Path, commit: str, host: str) -> dict:
    if not HEX_COMMIT.fullmatch(commit): raise ValueError("RELEASE_COMMIT_INVALID")
    if not crate.is_file() or not offline.is_file(): raise ValueError("RELEASE_ARTIFACT_MISSING")
    contracts=[]
    for path in sorted((root/"contracts").glob("*.schema.json")):
        contracts.append({"path":str(path.relative_to(root)),"sha256":sha256(path)})
    return {
      "schema":"iicp.management-release-manifest.v1",
      "product":"iicp-management-core",
      "version":version(root/"Cargo.toml"),
      "channel":"developer-preview",
      "commit":commit,
      "validated_target":host,
      "artifacts":{
        "crate":{"path":crate.name,"sha256":sha256(crate)},
        "offline_bundle":{"path":offline.name,"sha256":sha256(offline)},
      },
      "contracts":contracts,
      "binaries":["iicp-management","iicp-management-controller","iicp-management-conformance"],
      "known_limitations":[
        "domain-local controller only",
        "no remote administration service",
        "no production service installer",
        "no Directory advertisement",
        "no package publication or deployment implied",
      ],
      "authorizes_publication":False,
      "authorizes_deployment":False,
    }

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path(".")); p.add_argument("--crate",type=Path,required=True)
    p.add_argument("--offline-bundle",type=Path,required=True); p.add_argument("--commit")
    p.add_argument("--host"); p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(); root=a.root.resolve()
    commit=a.commit or subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    host=a.host or next(line.split(": ",1)[1] for line in subprocess.check_output(["rustc","-vV"],text=True).splitlines() if line.startswith("host: "))
    data=build(root,a.crate.resolve(),a.offline_bundle.resolve(),commit,host)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    print(a.output)
    return 0
if __name__=="__main__": raise SystemExit(main())
