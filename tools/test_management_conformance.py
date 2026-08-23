#!/usr/bin/env python3
import json, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class TestPortableConformance(unittest.TestCase):
 def test_pack(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/"report.json"
   subprocess.run(["python3",str(ROOT/"tools/run_management_conformance.py"),str(ROOT/"fixtures/management-portable-conformance-v1.json"),"--output",str(out)],check=True)
   report=json.loads(out.read_text()); self.assertEqual(report["failed"],0); self.assertEqual(report["passed"],11); self.assertEqual(report["evidence_class"],"project-verified")
if __name__ == "__main__": unittest.main()
