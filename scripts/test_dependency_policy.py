#!/usr/bin/env python3
import sys
import tomllib
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_dependency_policy import violations

class DependencyPolicyTests(unittest.TestCase):
    def lock(self, body: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "Cargo.lock"
        path.write_text(body)
        return path

    def test_accepts_crates_io_and_local_root(self):
        path = self.lock('[[package]]\nname="safe"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="local"\nversion="0.1.0"\n')
        self.assertEqual(violations(path), [])

    def test_rejects_every_incident_name_and_version(self):
        packages = [
            ("arrayref", "0.3.10"), ("internment", "0.8.7"),
            ("append-only-vec", "0.1.9"), ("proc-macro1", "1.0.0"),
            ("proc-macro-en", "1.0.0"), ("aovine", "1.0.0"),
            ("arone", "1.0.0"), ("aronenao", "1.0.0"),
            ("tinymember", "1.0.0"),
        ]
        body = "".join(f'[[package]]\nname="{name}"\nversion="{version}"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n' for name, version in packages)
        result = violations(self.lock(body))
        for name, _ in packages:
            self.assertTrue(any(name in item for item in result), name)

    def test_rejects_git_and_unknown_registries(self):
        path = self.lock('[[package]]\nname="git-dep"\nversion="1.0.0"\nsource="git+https://example.test/repo"\n[[package]]\nname="mirror"\nversion="1.0.0"\nsource="registry+https://example.test/index"\n')
        result = violations(path)
        self.assertEqual(sum("unapproved source" in item for item in result), 2)

    def test_rejects_rustls_advisory_range(self):
        for patch in range(13, 45):
            with self.subTest(patch=patch):
                self.assertEqual(violations(self.lock(f'[[package]]\nname="rustls"\nversion="0.23.{patch}"\n')), [f"denied package rustls 0.23.{patch}"])

    def test_newly_affected_prior_boundaries_are_denied(self):
        for version in ["0.23.12", "0.23.45"]:
            with self.subTest(version=version):
                self.assertEqual(violations(self.lock(f'[[package]]\nname="rustls"\nversion="{version}"\n')), [f"denied package rustls {version}"])

    def test_downstream_dependency_has_patched_security_floor(self):
        config = tomllib.loads((Path(__file__).resolve().parents[1] / "Cargo.toml").read_text())
        self.assertEqual(config["dependencies"]["rustls"], {"version": "0.23.46", "default-features": False})


class CurrentDependencySecurityTests(unittest.TestCase):
    def check_pair(self, name, version, source="registry+https://github.com/rust-lang/crates.io-index"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.lock"
            path.write_text(f'[[package]]\nname="{name}"\nversion="{version}"\nsource="{source}"\n')
            return violations(path)

    def test_current_affected_series_are_denied(self):
        series = [("rustls", "0.23", 46), ("rustls-webpki", "0.103", 16),
                  ("webpki-roots", "1.0", 10), ("quinn-proto", "0.11", 18),
                  ("tokio", "1.51", 6), ("tokio", "1.52", 4), ("tokio", "1.53", 3)]
        for name, prefix, patches in series:
            for patch in range(patches):
                version = f"{prefix}.{patch}"
                with self.subTest(name=name, version=version):
                    self.assertEqual(self.check_pair(name, version), [f"denied package {name} {version}"])

    def test_patched_and_unaffected_controls_remain_usable(self):
        for name, version in [("rustls", "0.23.46"), ("rustls-webpki", "0.103.16"),
                              ("webpki-roots", "1.0.10"), ("webpki-roots", "0.26.11"),
                              ("quinn-proto", "0.11.18"), ("tokio", "1.51.6"),
                              ("tokio", "1.53.3"), ("safe", "1.0.0")]:
            with self.subTest(name=name, version=version):
                self.assertEqual(self.check_pair(name, version), [])

    def test_registry_is_not_widened_by_patched_version(self):
        self.assertEqual(self.check_pair("rustls", "0.23.46", "git+https://example.invalid/repo"),
                         ["unapproved source for rustls 0.23.46: git+https://example.invalid/repo"])

    def test_active_tls_floors_do_not_enable_defaults(self):
        config = tomllib.loads((Path(__file__).resolve().parents[1] / "Cargo.toml").read_text())
        deps = config["dependencies"]
        for name, version in [("rustls", "0.23.46"), ("rustls-webpki", "0.103.16"),
                              ("webpki-roots", "1.0.10")]:
            self.assertEqual(deps[name], {"version": version, "default-features": False})
        self.assertEqual(deps["tokio"]["version"], "1.53.3")
        if config["package"]["name"] == "iicp-management-core":
            self.assertEqual(deps["tokio"], {"version": "1.53.3", "default-features": False})
            self.assertEqual(config["dev-dependencies"]["tokio"]["version"], "1.53.3")

    def test_current_lock_contains_no_explicit_denied_pairs(self):
        self.assertEqual(violations(Path(__file__).resolve().parents[1] / "Cargo.lock"), [])

if __name__ == "__main__":
    unittest.main()
