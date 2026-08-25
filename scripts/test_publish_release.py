#!/usr/bin/env python3
import sys
import os
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publish_release import ReleaseError, ReleaseState, execute, planned_actions, verify_registry_checksum


class PublicationStateTests(unittest.TestCase):
    def test_new_release_runs_every_stage(self):
        self.assertEqual(
            planned_actions(ReleaseState(False, False, False, False, False)),
            ["readiness", "publish_crate", "create_tag", "push_tag", "create_release", "verify"],
        )

    def test_resume_after_crate_publication(self):
        self.assertEqual(
            planned_actions(ReleaseState(True, False, False, False, True)),
            ["create_tag", "push_tag", "create_release", "verify"],
        )

    def test_resume_after_tag(self):
        self.assertEqual(
            planned_actions(ReleaseState(True, True, True, False, True)),
            ["create_release", "verify"],
        )

    def test_complete_release_only_verifies(self):
        self.assertEqual(planned_actions(ReleaseState(True, False, True, True, False)), ["verify"])

    def test_resume_after_local_tag_creation(self):
        self.assertEqual(
            planned_actions(ReleaseState(True, True, False, False, True)),
            ["push_tag", "create_release", "verify"],
        )

    def test_partial_state_never_republishes_or_invents_artifacts(self):
        with self.assertRaisesRegex(ReleaseError, "RECOVERY_ARTIFACTS_MISSING"):
            planned_actions(ReleaseState(True, False, False, False, False))
        with self.assertRaisesRegex(ReleaseError, "TAG_WITHOUT_CRATE"):
            planned_actions(ReleaseState(False, True, False, False, True))
        with self.assertRaisesRegex(ReleaseError, "RELEASE_WITHOUT_TAG"):
            planned_actions(ReleaseState(True, False, False, True, True))

    @patch("publish_release.crate_published", return_value=False)
    @patch("publish_release.preflight", return_value=("a" * 40, "0.1.0", False, False, False))
    def test_missing_credential_fails_before_readiness(self, _preflight, _published):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ReleaseError, "CARGO_REGISTRY_TOKEN_REQUIRED"):
                execute(Path("."), "0.1.0")

    @patch("publish_release.preflight", return_value=("a" * 40, "0.1.0", False, False, False))
    def test_confirmation_must_match_exact_version(self, _preflight):
        with self.assertRaisesRegex(ReleaseError, "RELEASE_CONFIRMATION_MISMATCH"):
            execute(Path("."), "latest")

    def test_publisher_uses_locked_cargo_and_never_accepts_token_argument(self):
        text = Path("scripts/publish_release.py").read_text()
        self.assertIn('["cargo", "publish", "--locked"]', text)
        self.assertNotIn('"--token"', text)
        self.assertIn("CARGO_REGISTRY_TOKEN_REQUIRED", text)

    @patch("publish_release.registry_checksum", return_value="b" * 64)
    @patch("publish_release.sha256", return_value="sha256:" + "a" * 64)
    def test_registry_and_readiness_crate_must_match(self, _sha, _checksum):
        with self.assertRaisesRegex(ReleaseError, "REGISTRY_CRATE_DIGEST_MISMATCH"):
            verify_registry_checksum("0.1.0", Path("unused"))


if __name__ == "__main__":
    unittest.main()
