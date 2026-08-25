#!/usr/bin/env python3
import sys
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

if __name__ == "__main__":
    unittest.main()
