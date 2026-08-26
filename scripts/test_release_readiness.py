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
        self.assertIn('online-cargo-home', self.text)
    def test_packaged_diagnostic_contract_is_exercised(self):
        for value in ('contracts/diagnostic-bundle-v1.schema.json', 'fixtures/diagnostic-bundle-conformance-v1.json', 'docs/ADR-009-diagnostic-bundles-are-minimized-evidence.md', 'docs/DIAGNOSTIC_BUNDLE_WORKFLOW.md', 'contracts/diagnostic-bundle-v2.schema.json', 'fixtures/diagnostic-bundle-conformance-v2.json', 'docs/ADR-013-runtime-health-is-non-authorizing-observation.md'):
            self.assertIn(value, self.text)
        self.assertIn('diagnostics verify', self.text)
        self.assertIn('diagnostics show', self.text)
        self.assertIn('tools/run_diagnostic_v2_conformance.py', self.text)
        self.assertIn('--runtime-health', self.text)
        self.assertIn('--runtime-target', self.text)
        self.assertIn('partial runtime diagnostic flags did not fail closed', self.text)
    def test_refuses_existing_release_tag_and_never_publishes(self):
        self.assertIn('git ls-remote --exit-code --tags',self.text)
        self.assertNotIn('cargo publish',self.text); self.assertNotIn('gh release create',self.text)
    def test_offline_install_is_exercised(self):
        self.assertIn('cargo vendor --locked',self.text); self.assertIn('cargo install --offline --locked',self.text)
        self.assertIn('exercise_trial "$offline_install/bin/iicp-management" offline', self.text)
    def test_administrator_trial_candidate_is_packaged_and_exercised(self):
        self.assertIn('contracts/administrator-trial-v2.schema.json', self.text)
        self.assertIn('fixtures/administrator-trial-conformance-v2.json', self.text)
        self.assertIn('trial summarize', self.text)
        self.assertIn('release_gate_authorized', self.text)
if __name__=="__main__": unittest.main()
