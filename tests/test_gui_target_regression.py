"""Tes regresi: hasil DNS/WHOIS menyimpan target yang benar di riwayat.

Memperbaiki bug target kosong: DnsLookupTab._run dan WhoisLookupTab._run
kini menambahkan result["target"]. Scanner dimock (tanpa jaringan), prinsip
sama dengan test_gui.py: Tk root di-withdraw, widget hanya disentuh dari
main thread.
"""

import os
import tempfile
import tkinter as tk
import unittest
from unittest import mock

from config.settings import Config
from database.models import DatabaseManager
from database.queries import save_scan_session_result
from gui.scan_tabs import DnsLookupTab, WhoisLookupTab
from gui.worker import TaskRunner


class _TabTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Config(os.path.join(self.tmp.name, "config.json"))
        self.runner = TaskRunner(self.root)
        self.target_var = tk.StringVar()

    def tearDown(self):
        try:
            if self.root.winfo_exists():
                self.root.update()
                self.root.destroy()
        except tk.TclError:
            pass


class DnsLookupTargetTest(_TabTestCase):
    def _make_tab(self):
        return DnsLookupTab(self.root, self.config, self.runner,
                            self.target_var, lambda s: None,
                            lambda r, s: None)

    def test_run_adds_target_matching_input(self):
        self.target_var.set("contoh.example")
        tab = self._make_tab()
        with mock.patch("gui.scan_tabs.lookup_records",
                        return_value={"domain": "contoh.example",
                                      "records": {"A": ["1.1.1.1"]},
                                      "errors": {}}):
            result = tab._run(None, None)
        self.assertEqual(result["target"], "contoh.example")
        self.assertEqual(result["scan_type"], "dns_lookup")

    def test_saved_history_keeps_target(self):
        self.target_var.set("contoh.example")
        tab = self._make_tab()
        db = DatabaseManager(os.path.join(self.tmp.name, "scans.db"))
        with mock.patch("gui.scan_tabs.lookup_records",
                        return_value={"domain": "contoh.example",
                                      "records": {"MX": ["mail.example"]},
                                      "errors": {}}):
            result = tab._run(None, None)
        session_id = save_scan_session_result(db, result)
        row = db.get_scan_by_id(session_id)
        self.assertEqual(row[1], "contoh.example")


class WhoisLookupTargetTest(_TabTestCase):
    def _make_tab(self):
        return WhoisLookupTab(self.root, self.config, self.runner,
                              self.target_var, lambda s: None,
                              lambda r, s: None)

    def test_run_adds_target_and_keeps_domain(self):
        self.target_var.set("contoh.example")
        tab = self._make_tab()
        with mock.patch("gui.scan_tabs.whois_lookup",
                        return_value={"domain": "contoh.example",
                                      "server": "whois.example",
                                      "raw_response": "x", "error": None}):
            result = tab._run(None, None)
        self.assertEqual(result["target"], "contoh.example")
        self.assertEqual(result["domain"], "contoh.example")

    def test_run_falls_back_to_input_when_domain_missing(self):
        self.target_var.set("contoh.example")
        tab = self._make_tab()
        with mock.patch("gui.scan_tabs.whois_lookup",
                        return_value={"server": "whois.iana.org",
                                      "raw_response": "", "error": "x"}):
            result = tab._run(None, None)
        self.assertEqual(result["target"], "contoh.example")

    def test_saved_history_keeps_target(self):
        self.target_var.set("contoh.example")
        tab = self._make_tab()
        db = DatabaseManager(os.path.join(self.tmp.name, "scans.db"))
        with mock.patch("gui.scan_tabs.whois_lookup",
                        return_value={"domain": "contoh.example",
                                      "server": "whois.example",
                                      "raw_response": "x", "error": None}):
            result = tab._run(None, None)
        session_id = save_scan_session_result(db, result)
        row = db.get_scan_by_id(session_id)
        self.assertEqual(row[1], "contoh.example")
