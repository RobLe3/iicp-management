#!/usr/bin/env python3
import importlib.util, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location("runner",Path("tools/run_diagnostic_v2_conformance.py"))
runner=importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
class DiagnosticV2ConformanceTest(unittest.TestCase):
    def test_fixture_passes(self):
        result=runner.run("fixtures/diagnostic-bundle-conformance-v2.json")
        self.assertTrue(result["passed"])
        self.assertEqual(len(result["results"]),9)
    def test_tamper_fails_closed(self):
        actual=runner.classify({"scenario":"semantic_inconsistency","input":{"evidence_state":"current","liveness":"live","readiness":"ready","claimed_effective_state":"not_ready"}})
        self.assertEqual(actual,{"result":"reject","reason":"DIAGNOSTIC_RUNTIME_INVALID"})
if __name__ == "__main__": unittest.main()
