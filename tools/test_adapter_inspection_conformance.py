#!/usr/bin/env python3
import json, subprocess, sys, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class AdapterInspectionConformanceTests(unittest.TestCase):
    def test_fixture_passes(self):
        result=subprocess.run([sys.executable,str(ROOT/'tools/run_adapter_inspection_conformance.py'),str(ROOT/'fixtures/adapter-inspection-conformance-v1.json')],capture_output=True,text=True,check=True)
        report=json.loads(result.stdout)
        self.assertEqual(report['passed'],7)
        self.assertEqual(report['failed'],0)
if __name__=='__main__': unittest.main()
