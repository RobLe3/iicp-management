#!/usr/bin/env python3

import unittest

from check_public_references import findings


class PublicReferenceTests(unittest.TestCase):
    def test_public_project_repository_is_allowed(self):
        self.assertEqual(findings("https://github.com/RobLe3/IICP"), [])

    def test_unavailable_repository_is_rejected_without_naming_real_private_assets(self):
        name = "unavailable" + "-component"
        self.assertEqual(findings("RobLe3/" + name), [name])


if __name__ == "__main__":
    unittest.main()
