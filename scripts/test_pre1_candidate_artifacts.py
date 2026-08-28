from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_description_names_primary_and_all_binaries(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "management")
        self.assertEqual(value["target_artifact"], "binary")
        self.assertEqual(value["portable_artifacts_on"], "macos-arm64")
        self.assertEqual(len(value["binary_bundle_members"]), 3)
        self.assertTrue(value["non_authorizing"])


if __name__ == "__main__":
    unittest.main()
