#!/usr/bin/env python3
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuntimeObservationConformanceTests(unittest.TestCase):
    def test_fixture_passes(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/run_runtime_observation_conformance.py"), str(ROOT / "fixtures/runtime-observation-conformance-v1.json")],
            capture_output=True, text=True, check=True,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["passed"], 5)
        self.assertEqual(report["failed"], 0)


if __name__ == "__main__":
    unittest.main()
