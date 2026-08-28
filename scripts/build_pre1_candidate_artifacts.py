#!/usr/bin/env python3
"""Build and prove one Management target artifact fragment."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

import pre1_artifact_common as common
import pre1_rust_build as rust_build


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "management"
TARGETS = {
    "linux-x86_64",
    "linux-aarch64",
    "macos-x86_64",
    "macos-arm64",
    "windows-x86_64",
}
PRIMARY_TARGET = "macos-arm64"
BINARIES = [
    "iicp-management",
    "iicp-management-controller",
    "iicp-management-conformance",
]


def describe() -> dict:
    return {
        "schema": "iicp.pre1-artifact-builder-description.v1",
        "component": COMPONENT,
        "target_artifact": "binary",
        "portable_artifacts_on": PRIMARY_TARGET,
        "portable_artifacts": ["crate", "release-manifest"],
        "binary_bundle_members": BINARIES,
        "gates": sorted(common.GATES),
        "requires_clean_source": True,
        "non_authorizing": True,
    }


def build(destination: Path, requested_target: str | None) -> dict:
    common.safe_output(destination)
    target = common.require_target(requested_target, TARGETS)
    commit = common.require_clean_source(ROOT)
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    if package.get("rust-version") != "1.86":
        raise ValueError("Management MSRV differs from the qualification policy")
    run_root = Path(tempfile.mkdtemp(prefix="iicp-pre1-management-", dir=destination.parent))
    staging = run_root / "fragment"
    staging.mkdir()
    try:
        quality_env = rust_build.cargo_environment(run_root, "quality")
        common.run(["cargo", "test", "--locked"], ROOT, quality_env)
        common.run(["cargo", "build", "--release", "--locked", "--bins"], ROOT, quality_env)
        crate, extracted, offline_source, cache_digest = rust_build.package_and_vendor(
            ROOT, run_root, "iicp-management-core", version
        )
        online = rust_build.install_and_report(
            ROOT, run_root, extracted, "iicp-management", version, offline=False
        )
        offline = rust_build.install_and_report(
            ROOT,
            run_root,
            offline_source / "source",
            "iicp-management",
            version,
            offline=True,
        )
        if online != offline:
            raise ValueError("online and offline Management self-reports differ")

        binary_source = run_root / "binary-bundle"
        binary_source.mkdir()
        suffix = ".exe" if os.name == "nt" else ""
        for name in BINARIES:
            source = Path(quality_env["CARGO_TARGET_DIR"]) / "release" / (name + suffix)
            if not source.is_file():
                raise ValueError(f"Management release binary is unavailable: {name}")
            shutil.copyfile(source, binary_source / (name + suffix))
        binary_bundle = staging / f"iicp-management-{version}-{target}.tar.gz"
        rust_build.deterministic_tar(binary_source, binary_bundle)
        artifacts = [common.artifact("binary", target, binary_bundle)]
        if target == PRIMARY_TARGET:
            copied_crate = staging / crate.name
            shutil.copyfile(crate, copied_crate)
            artifacts.append(common.artifact("crate", "any", copied_crate))
            release_manifest = staging / f"iicp-management-{version}-release-manifest.json"
            release_manifest.write_text(
                json.dumps(
                    {
                        "schema": "iicp.pre1-management-release-manifest.v1",
                        "product": "iicp-management-core",
                        "version": version,
                        "source_commit": commit,
                        "channel": "developer-preview",
                        "binaries": BINARIES,
                        "management_service": False,
                        "directory_authority": False,
                        "publication_authorized": False,
                        "deployment_authorized": False,
                        "non_authorizing": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            artifacts.append(common.artifact("release-manifest", "any", release_manifest))
        fragment = common.emit_fragment(
            staging,
            component=COMPONENT,
            source_commit=commit,
            source_version=version,
            build_target=target,
            artifacts=artifacts,
            lock_inputs_sha256=common.files_sha256(
                ROOT, [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
            ),
            dependency_cache_sha256=cache_digest,
            toolchains={
                "cargo": common.output(["cargo", "--version"], ROOT),
                "rustc": common.output(["rustc", "--version"], ROOT),
            },
        )
        common.publish_staging(staging, destination)
        return fragment
    finally:
        common.clean_failed_staging(run_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --describe is used")
    try:
        value = build(args.output.resolve(), args.target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
