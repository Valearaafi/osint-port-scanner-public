"""Tes regresi Config (T6): mutasi hasil load tidak mengubah default_config."""

import json
import os
import tempfile
import unittest

from config.settings import Config


class ConfigDefaultIsolationTest(unittest.TestCase):
    def test_set_after_missing_file_does_not_mutate_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(os.path.join(tmp, "config.json"))
            self.assertEqual(config.default_config["scan_settings"]["timeout"], 5)
            config.set("scan_settings.timeout", 99)
            config.set("scan_settings.common_ports", [1, 2])
            self.assertEqual(config.default_config["scan_settings"]["timeout"], 5)
            self.assertGreater(len(config.default_config["scan_settings"]
                                   ["common_ports"]), 2)
            fresh = Config(os.path.join(tmp, "lain.json"))
            self.assertEqual(fresh.get("scan_settings.timeout"), 5)

    def test_set_on_merged_missing_section_does_not_mutate_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"scan_settings": {"timeout": 7}}, fh)  # tanpa reporting
            config = Config(path)
            self.assertEqual(config.get("reporting.default_format"), "pdf")
            config.set("reporting.default_format", "html")
            self.assertEqual(
                config.default_config["reporting"]["default_format"], "pdf")

    def test_corrupt_file_fallback_does_not_mutate_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{ korup")
            config = Config(path)
            config.set("scan_settings.max_threads", 7)
            self.assertEqual(
                config.default_config["scan_settings"]["max_threads"], 50)


if __name__ == "__main__":
    unittest.main()
