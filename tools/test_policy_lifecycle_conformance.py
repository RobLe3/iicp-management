import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "run_policy_lifecycle_conformance.py"
FIXTURE = ROOT / "fixtures" / "policy-lifecycle-conformance-v1.json"


class PolicyLifecycleConformanceTest(unittest.TestCase):
    def test_reference_runner_passes_all_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            result = subprocess.run(
                [sys.executable, str(RUNNER), str(FIXTURE), "--output", str(output)],
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            report = json.loads(output.read_text())
            self.assertEqual(report["passed"], 8)
            self.assertEqual(report["failed"], 0)
            self.assertEqual(len({case["id"] for case in report["results"]}), 8)


if __name__ == "__main__":
    unittest.main()
