"""The fixture parser must reject broken control inputs, not count them as vectors."""
import copy
from pathlib import Path
import tempfile
import unittest

from run_external_evaluator_development_conformance import load_fixture, validate_pack


class ExperimentalFixtureTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_fixture(
            Path(__file__).resolve().parents[1]
            / "tests/fixtures/management-external-evaluator-development-v1.json"
        )

    def test_fixture_is_valid(self):
        validate_pack(self.pack)

    def test_malformed_controls_do_not_become_passing_negative_vectors(self):
        mutations = {
            "config": lambda p: p["fixture_context"].update(max_validity=True),
            "request": lambda p: p["request"].update(policy_generation=True),
            "baseline": lambda p: p["result"].update(authorizes_mutation=True),
            "cases": lambda p: p["cases"].insert(0, copy.deepcopy(p["cases"][0])),
            "case clock": lambda p: p["cases"][0].update(checked_at=True),
            "negative control": lambda p: p["cases"][0].update(local_policy="unknown"),
            "extra override": lambda p: p["cases"][0].update(result_overrides={"typo": "allow"}),
            "expected outcome": lambda p: p["cases"][0]["expected"].update(authorizes_mutation=0),
            "derivation": lambda p: p["cases"][0].update(derivation="  "),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = copy.deepcopy(self.pack)
                mutate(value)
                with self.assertRaises(ValueError):
                    validate_pack(value)

    def test_removing_any_current_vector_refuses_the_incomplete_pack(self):
        for missing in self.pack["cases"]:
            with self.subTest(case=missing["id"]):
                value = copy.deepcopy(self.pack)
                value["cases"] = [case for case in value["cases"] if case["id"] != missing["id"]]
                with self.assertRaisesRegex(ValueError, "missing required vectors: " + missing["id"]):
                    validate_pack(value)

    def test_additional_vector_does_not_change_the_required_floor(self):
        additive = copy.deepcopy(self.pack["cases"][0])
        additive["id"] = "EE1-OPTIONAL-ADDITIONAL-CONTROL"
        self.pack["cases"].append(additive)
        validate_pack(self.pack)

    def test_disallowed_json_encodings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            for raw in (b'{"status": "a", "status": "b"}', b'{"checked_at": NaN}'):
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        load_fixture(path)


if __name__ == "__main__":
    unittest.main()
