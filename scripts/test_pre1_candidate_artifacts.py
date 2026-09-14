from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_binary_copy_preserves_executable_mode(self) -> None:
        import build_pre1_candidate_artifacts as builder

        if builder.os.name == "nt":
            self.skipTest("Windows does not use POSIX executable mode bits")
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            destination = Path(temporary) / "destination"
            source.write_bytes(b"binary")
            source.chmod(0o755)
            builder.copy_binary(source, destination)
            self.assertTrue(destination.stat().st_mode & 0o111)

    def test_disposable_windows_path_prefix_is_short(self) -> None:
        import build_pre1_candidate_artifacts as builder
        from unittest import mock
        with mock.patch.object(builder.os, "name", "nt"):
            self.assertEqual(builder.run_directory_prefix(), "mg-")
        with mock.patch.object(builder.os, "name", "posix"):
            self.assertEqual(builder.run_directory_prefix(), "iicp-pre1-management-")

    def test_description_names_primary_and_all_binaries(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "management")
        self.assertEqual(value["target_artifact"], "binary")
        self.assertEqual(value["portable_artifacts_on"], "macos-arm64")
        self.assertEqual(len(value["binary_bundle_members"]), 3)
        self.assertTrue(value["non_authorizing"])


from test_pre1_command_observation import CommandObservationTests


if __name__ == "__main__":
    unittest.main()
