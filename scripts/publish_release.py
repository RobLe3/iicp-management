#!/usr/bin/env python3
"""Guarded, resumable local publisher for the management developer preview."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

PACKAGE = "iicp-management-core"
REPOSITORY = "RobLe3/iicp-management"
STABLE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseState:
    crate_published: bool
    local_tag_exists: bool
    remote_tag_exists: bool
    release_exists: bool
    artifacts_ready: bool


def planned_actions(state: ReleaseState) -> list[str]:
    if state.release_exists and not state.remote_tag_exists:
        raise ReleaseError("RELEASE_WITHOUT_TAG")
    if (state.local_tag_exists or state.remote_tag_exists) and not state.crate_published:
        raise ReleaseError("TAG_WITHOUT_CRATE")
    if state.release_exists and not state.crate_published:
        raise ReleaseError("RELEASE_WITHOUT_CRATE")
    if state.release_exists:
        return ["verify"]
    if state.crate_published and not state.artifacts_ready:
        raise ReleaseError("RECOVERY_ARTIFACTS_MISSING")
    actions: list[str] = []
    if not state.crate_published:
        actions.extend(["readiness", "publish_crate"])
    if not state.remote_tag_exists:
        if not state.local_tag_exists:
            actions.append("create_tag")
        actions.append("push_tag")
    actions.extend(["create_release", "verify"])
    return actions


def run(args: list[str], *, root: Path, capture: bool = False, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=root,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def package_version(root: Path) -> str:
    return tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]


def validate_release_version(version: str) -> None:
    if not STABLE_VERSION.fullmatch(version):
        raise ReleaseError("RELEASE_VERSION_INVALID")


def registry_checksum(version: str) -> str | None:
    url = f"https://crates.io/api/v1/crates/{PACKAGE}/{version}"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            if response.status != 200:
                return None
            value = json.load(response)
            checksum = value.get("version", {}).get("checksum")
            if not isinstance(checksum, str) or len(checksum) != 64:
                raise ReleaseError("REGISTRY_CHECKSUM_INVALID")
            return checksum
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"REGISTRY_QUERY_FAILED:{exc.code}") from exc
    except OSError as exc:
        raise ReleaseError("REGISTRY_QUERY_FAILED") from exc


def crate_published(version: str) -> bool:
    return registry_checksum(version) is not None


def verify_registry_checksum(version: str, crate: Path) -> None:
    checksum = registry_checksum(version)
    if checksum is None:
        raise ReleaseError("REGISTRY_VERSION_MISSING")
    if checksum != sha256(crate).removeprefix("sha256:"):
        raise ReleaseError("REGISTRY_CRATE_DIGEST_MISMATCH")


def artifact_paths(root: Path, version: str) -> tuple[Path, Path, Path]:
    output = root / "target" / "release-readiness"
    return (
        output / f"{PACKAGE}-{version}.crate",
        output / f"{PACKAGE}-{version}-offline.tar.gz",
        output / "release-manifest.json",
    )


def artifacts_ready(root: Path, version: str) -> bool:
    return all(path.is_file() for path in artifact_paths(root, version))


def cargo_credentials_available(env: dict[str, str], home: Path) -> bool:
    if env.get("CARGO_REGISTRY_TOKEN"):
        return True
    cargo_home = Path(env.get("CARGO_HOME", home / ".cargo"))
    for path in (cargo_home / "credentials.toml", cargo_home / "credentials"):
        if not path.is_file():
            continue
        if path.stat().st_mode & 0o077:
            raise ReleaseError("CARGO_CREDENTIAL_PERMISSIONS_UNSAFE")
        return True
    return False


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def verify_artifacts(root: Path, head: str, version: str) -> tuple[Path, Path, Path]:
    crate, offline, manifest_path = artifact_paths(root, version)
    if not all(path.is_file() for path in (manifest_path, crate, offline)):
        raise ReleaseError("RELEASE_ARTIFACT_MISSING")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("commit") != head or manifest.get("version") != version:
        raise ReleaseError("RELEASE_MANIFEST_IDENTITY_MISMATCH")
    if manifest.get("authorizes_publication") is not False or manifest.get("authorizes_deployment") is not False:
        raise ReleaseError("RELEASE_MANIFEST_AUTHORITY_INVALID")
    expected = {
        manifest["artifacts"]["crate"]["sha256"]: crate,
        manifest["artifacts"]["offline_bundle"]["sha256"]: offline,
    }
    if any(sha256(path) != digest for digest, path in expected.items()):
        raise ReleaseError("RELEASE_ARTIFACT_DIGEST_MISMATCH")
    return crate, offline, manifest_path


def validate_remote_release(
    release: dict, manifest: dict, manifest_digest: str, head: str, version: str, registry_digest: str
) -> None:
    if release.get("tagName") != f"v{version}" or release.get("isPrerelease") is not True:
        raise ReleaseError("REMOTE_RELEASE_IDENTITY_INVALID")
    if manifest.get("commit") != head or manifest.get("version") != version:
        raise ReleaseError("REMOTE_MANIFEST_IDENTITY_MISMATCH")
    if manifest.get("authorizes_publication") is not False or manifest.get("authorizes_deployment") is not False:
        raise ReleaseError("REMOTE_MANIFEST_AUTHORITY_INVALID")
    expected = {
        f"{PACKAGE}-{version}.crate": manifest["artifacts"]["crate"]["sha256"],
        f"{PACKAGE}-{version}-offline.tar.gz": manifest["artifacts"]["offline_bundle"]["sha256"],
        "release-manifest.json": manifest_digest,
    }
    actual = {asset.get("name"): asset.get("digest") for asset in release.get("assets", [])}
    if actual != expected:
        raise ReleaseError("REMOTE_RELEASE_ASSET_DIGEST_MISMATCH")
    if registry_digest != expected[f"{PACKAGE}-{version}.crate"].removeprefix("sha256:"):
        raise ReleaseError("REMOTE_REGISTRY_DIGEST_MISMATCH")


def verify_remote_release(root: Path, head: str, version: str) -> None:
    release = json.loads(
        run(
            ["gh", "release", "view", f"v{version}", "--repo", REPOSITORY, "--json", "tagName,isPrerelease,assets"],
            root=root,
            capture=True,
        )
    )
    local_manifest = artifact_paths(root, version)[2]
    if local_manifest.is_file():
        manifest_path = local_manifest
        temporary = None
    else:
        temporary = tempfile.TemporaryDirectory()
        run(
            [
                "gh", "release", "download", f"v{version}", "--repo", REPOSITORY,
                "--pattern", "release-manifest.json", "--dir", temporary.name,
            ],
            root=root,
        )
        manifest_path = Path(temporary.name) / "release-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
        checksum = registry_checksum(version)
        if checksum is None:
            raise ReleaseError("REGISTRY_VERSION_MISSING")
        validate_remote_release(release, manifest, sha256(manifest_path), head, version, checksum)
    finally:
        if temporary is not None:
            temporary.cleanup()


def preflight(root: Path) -> tuple[str, str, bool, bool, bool]:
    if run(["git", "branch", "--show-current"], root=root, capture=True) != "main":
        raise ReleaseError("RELEASE_REQUIRES_MAIN")
    if run(["git", "status", "--porcelain"], root=root, capture=True):
        raise ReleaseError("RELEASE_REQUIRES_CLEAN_WORKTREE")
    head = run(["git", "rev-parse", "HEAD"], root=root, capture=True)
    if head != run(["git", "rev-parse", "origin/main"], root=root, capture=True):
        raise ReleaseError("RELEASE_REQUIRES_ORIGIN_MAIN")
    version = package_version(root)
    validate_release_version(version)
    if not (root / "docs" / f"RELEASE_NOTES_{version}.md").is_file():
        raise ReleaseError("RELEASE_NOTES_MISSING")
    tag = f"v{version}"
    local_tag = bool(run(["git", "tag", "--list", tag], root=root, capture=True))
    if local_tag and run(["git", "rev-list", "-n", "1", tag], root=root, capture=True) != head:
        raise ReleaseError("RELEASE_LOCAL_TAG_TARGET_MISMATCH")
    tag_result = subprocess.run(
        ["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    tag_lines = [line.split() for line in tag_result.stdout.splitlines() if line.strip()]
    remote_tag = bool(tag_lines)
    if remote_tag:
        target = next((value for value, ref in tag_lines if ref.endswith("^{}")), tag_lines[0][0])
        if target != head:
            raise ReleaseError("RELEASE_TAG_TARGET_MISMATCH")
    release_exists = subprocess.run(
        ["gh", "release", "view", tag, "--repo", REPOSITORY],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    return head, version, local_tag, remote_tag, release_exists


def wait_for_registry(version: str) -> None:
    for _ in range(30):
        if crate_published(version):
            return
        time.sleep(2)
    raise ReleaseError("REGISTRY_VERIFICATION_TIMEOUT")


def execute(root: Path, confirmation: str) -> None:
    head, version, local_tag_exists, remote_tag_exists, release_exists = preflight(root)
    if confirmation != version:
        raise ReleaseError("RELEASE_CONFIRMATION_MISMATCH")
    published = crate_published(version)
    local_artifacts_ready = artifacts_ready(root, version)
    state = ReleaseState(published, local_tag_exists, remote_tag_exists, release_exists, local_artifacts_ready)
    actions = planned_actions(state)
    print("release actions: " + ", ".join(actions))

    if actions == ["verify"]:
        wait_for_registry(version)
        verify_remote_release(root, head, version)
        print(f"release publication verified: {PACKAGE} {version} at {head}")
        return

    if "readiness" in actions:
        if not cargo_credentials_available(os.environ, Path.home()):
            raise ReleaseError("CARGO_REGISTRY_CREDENTIAL_REQUIRED")
        run([str(root / "scripts" / "release_readiness.sh")], root=root)
    crate, offline, manifest = verify_artifacts(root, head, version)

    if "publish_crate" in actions:
        env = os.environ.copy()
        run(["cargo", "publish", "--locked"], root=root, env=env)
        wait_for_registry(version)
    verify_registry_checksum(version, crate)
    if "create_tag" in actions:
        run(["git", "tag", "-a", f"v{version}", "-m", f"IICP Management Foundation {version}"], root=root)
    if "push_tag" in actions:
        run(["git", "push", "origin", f"v{version}"], root=root)
    if "create_release" in actions:
        run(
            [
                "gh", "release", "create", f"v{version}", str(crate), str(offline), str(manifest),
                "--repo", REPOSITORY, "--verify-tag", "--prerelease",
                "--title", f"IICP Management Foundation {version} developer preview",
                "--notes-file", str(root / "docs" / f"RELEASE_NOTES_{version}.md"),
            ],
            root=root,
        )
    wait_for_registry(version)
    verify_remote_release(root, head, version)
    print(f"release publication verified: {PACKAGE} {version} at {head}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-version", default="")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if args.execute:
            execute(root, args.confirm_version)
        else:
            head, version, local_tag, remote_tag, release = preflight(root)
            state = ReleaseState(
                crate_published(version), local_tag, remote_tag, release, artifacts_ready(root, version)
            )
            print(json.dumps({"head": head, "version": version, "state": state.__dict__}, sort_keys=True))
    except (ReleaseError, subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
        print(f"release publication failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
