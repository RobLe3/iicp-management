#!/usr/bin/env python3
import re, unittest
from pathlib import Path

class ReleaseLaneContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text=Path("scripts/release_readiness.sh").read_text()
    def test_requires_clean_main_and_origin_main(self):
        self.assertIn('git branch --show-current',self.text); self.assertIn('git diff --quiet',self.text); self.assertIn('origin/main',self.text)
    def test_checks_policy_and_audit_before_compilation(self):
        policy=self.text.index('scripts/check_dependency_policy.py'); audit=self.text.index('cargo audit --no-fetch'); test=self.text.index('cargo test --locked')
        self.assertLess(policy,audit); self.assertLess(audit,test)
    def test_packages_and_installs_locked_without_unlocked_fallback(self):
        self.assertIn('cargo package --locked',self.text); self.assertGreaterEqual(self.text.count('cargo install --'),2)
        self.assertGreaterEqual(self.text.count('--locked --path'),2)
        self.assertNotRegex(self.text,r'cargo install(?![^\n]*--locked)')
    def test_refuses_existing_release_tag_and_never_publishes(self):
        self.assertIn('git ls-remote --exit-code --tags',self.text)
        self.assertNotIn('cargo publish',self.text); self.assertNotIn('gh release create',self.text)
    def test_offline_install_is_exercised(self):
        self.assertIn('cargo vendor --locked',self.text); self.assertIn('cargo install --offline --locked',self.text)
if __name__=="__main__": unittest.main()
