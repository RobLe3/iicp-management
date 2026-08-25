#!/usr/bin/env python3
import json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_release_manifest import build

class ManifestTests(unittest.TestCase):
    def root(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); root=Path(tmp.name)
        (root/"contracts").mkdir(); (root/"contracts/a.schema.json").write_text("{}\n")
        (root/"Cargo.toml").write_text('[package]\nname="iicp-management-core"\nversion="0.1.0"\n')
        crate=root/"package.crate"; crate.write_bytes(b"crate")
        offline=root/"offline.tar.gz"; offline.write_bytes(b"offline")
        return root,crate,offline
    def test_manifest_is_bounded_and_non_authorizing(self):
        root,crate,offline=self.root(); value=build(root,crate,offline,"a"*40,"test-host")
        self.assertEqual(value["version"],"0.1.0"); self.assertFalse(value["authorizes_publication"]); self.assertFalse(value["authorizes_deployment"])
        self.assertEqual(value["artifacts"]["crate"]["sha256"],"sha256:"+"f5fe331d2367a7a67ee20bd579c77b929ae49439d8b0d8e9c3b98609797b6b69")
    def test_rejects_bad_commit_and_missing_artifact(self):
        root,crate,offline=self.root()
        with self.assertRaisesRegex(ValueError,"RELEASE_COMMIT_INVALID"): build(root,crate,offline,"main","host")
        crate.unlink()
        with self.assertRaisesRegex(ValueError,"RELEASE_ARTIFACT_MISSING"): build(root,crate,offline,"b"*40,"host")
if __name__=="__main__": unittest.main()
