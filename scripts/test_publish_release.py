#!/usr/bin/env python3
import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publish_release import (
    ReleaseError,
    ReleaseState,
    cargo_credentials_available,
    execute,
    planned_actions,
    validate_remote_release,
    verify_registry_checksum,
)


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
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"HOME": directory}, clear=True), patch(
                "publish_release.Path.home", return_value=Path(directory)
            ):
                with self.assertRaisesRegex(ReleaseError, "CARGO_REGISTRY_CREDENTIAL_REQUIRED"):
                    execute(Path("."), "0.1.0")

    @patch("publish_release.preflight", return_value=("a" * 40, "0.1.0", False, False, False))
    def test_confirmation_must_match_exact_version(self, _preflight):
        with self.assertRaisesRegex(ReleaseError, "RELEASE_CONFIRMATION_MISMATCH"):
            execute(Path("."), "latest")

    def test_publisher_uses_locked_cargo_and_never_accepts_token_argument(self):
        text = Path("scripts/publish_release.py").read_text()
        self.assertIn('["cargo", "publish", "--locked"]', text)
        self.assertNotIn('"--token"', text)
        self.assertIn("CARGO_REGISTRY_CREDENTIAL_REQUIRED", text)

    def test_owner_only_cargo_login_file_is_accepted_without_reading_it(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            cargo_home = home / ".cargo"
            cargo_home.mkdir()
            credentials = cargo_home / "credentials.toml"
            credentials.write_text("secret material is never parsed by this test")
            credentials.chmod(0o600)
            self.assertTrue(cargo_credentials_available({}, home))
            credentials.chmod(0o644)
            with self.assertRaisesRegex(ReleaseError, "CARGO_CREDENTIAL_PERMISSIONS_UNSAFE"):
                cargo_credentials_available({}, home)

    @patch("publish_release.registry_checksum", return_value="b" * 64)
    @patch("publish_release.sha256", return_value="sha256:" + "a" * 64)
    def test_registry_and_readiness_crate_must_match(self, _sha, _checksum):
        with self.assertRaisesRegex(ReleaseError, "REGISTRY_CRATE_DIGEST_MISMATCH"):
            verify_registry_checksum("0.1.0", Path("unused"))

    def test_remote_release_binds_all_three_assets_and_registry(self):
        crate_digest = "sha256:" + "a" * 64
        offline_digest = "sha256:" + "b" * 64
        manifest_digest = "sha256:" + "c" * 64
        manifest = {
            "commit": "d" * 40,
            "version": "0.1.0",
            "authorizes_publication": False,
            "authorizes_deployment": False,
            "artifacts": {
                "crate": {"sha256": crate_digest},
                "offline_bundle": {"sha256": offline_digest},
            },
        }
        release = {
            "tagName": "v0.1.0",
            "isPrerelease": True,
            "assets": [
                {"name": "iicp-management-core-0.1.0.crate", "digest": crate_digest},
                {"name": "iicp-management-core-0.1.0-offline.tar.gz", "digest": offline_digest},
                {"name": "release-manifest.json", "digest": manifest_digest},
            ],
        }
        validate_remote_release(release, manifest, manifest_digest, "d" * 40, "0.1.0", "a" * 64)
        release["assets"][0]["digest"] = "sha256:" + "e" * 64
        with self.assertRaisesRegex(ReleaseError, "REMOTE_RELEASE_ASSET_DIGEST_MISMATCH"):
            validate_remote_release(release, manifest, manifest_digest, "d" * 40, "0.1.0", "a" * 64)


if __name__ == "__main__":
    unittest.main()
