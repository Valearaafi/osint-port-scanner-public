"""Unit test GUI Tahap 2-3.

Prinsip: hanya target localhost dengan listener sementara; DNS/WHOIS tidak
dipanggil lewat jaringan; messagebox/dialog dimock bila perlu; Tk root
di-withdraw. Tidak ada widget yang disentuh dari thread non-main.
"""

import csv
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import tkinter as tk
import unittest
from unittest import mock

from config.settings import Config
from database.models import DatabaseManager
from gui.exports import (
    CSV_PORT_COLUMNS,
    port_rows_for_csv,
    write_csv_ports,
    write_json_result,
)
from gui.main_window import PROJECT_ROOT, MainWindow, _default_data_dir
from gui.results_viewer import SortableTable, sort_key
from gui.scan_tabs import (
    HistoryTab,
    PortScannerTab,
    export_result,
    format_duration,
    format_summary,
    format_timestamp,
    label_port_status,
    label_scan_status,
    label_scan_type,
)
from gui.settings_dialog import SettingsDialog
from gui.worker import TaskRunner
from scanner.utils.threading_manager import CancellationToken
from tests.test_port_scanner import _EphemeralListener


def _pump(runner, timeout=10.0):
    """Pompa antrean TaskRunner secara manual, lalu pastikan worker keluar.

    join() penting: mencegah objek Tk difinalisasi di thread worker
    setelah test selesai (finalisasi lintas-thread merusak interp Tcl).
    """
    deadline = time.monotonic() + timeout
    while runner.busy and time.monotonic() < deadline:
        runner._poll()
        time.sleep(0.01)
    runner._poll()
    runner.wait(2.0)
    return not runner.busy


class _TkTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        try:
            if self.root.winfo_exists():
                self.root.update()  # flush event idle agar destroy bersih
                self.root.destroy()
        except tk.TclError:
            pass


class TaskRunnerTest(_TkTestCase):
    def setUp(self):
        super().setUp()
        self.runner = TaskRunner(self.root)

    def test_runs_target_reports_progress_then_done(self):
        events = []

        def target(progress_cb, token):
            progress_cb(1, 3, "a")
            progress_cb(2, 3, "b")
            return {"ok": True}

        self.assertTrue(self.runner.start(
            target, lambda r: events.append(("done", r)),
            lambda m: events.append(("error", m)),
            on_progress=lambda a, b, c: events.append(("progress", a, b, c))))
        self.assertTrue(_pump(self.runner))
        self.assertEqual(events[-1], ("done", {"ok": True}))
        self.assertEqual([e for e in events if e[0] == "progress"],
                         [("progress", 1, 3, "a"), ("progress", 2, 3, "b")])
        self.assertFalse(self.runner.busy)

    def test_refuses_second_task_while_busy(self):
        started = threading.Event()
        release = threading.Event()

        def target(progress_cb, token):
            started.set()
            release.wait(5)

        self.assertTrue(self.runner.start(target, lambda r: None, lambda m: None))
        self.assertTrue(started.wait(5))
        self.assertFalse(self.runner.start(target, lambda r: None, lambda m: None))
        release.set()
        self.assertTrue(_pump(self.runner))

    def test_error_reported_with_traceback(self):
        def target(progress_cb, token):
            raise RuntimeError("rusak")

        errors = []
        self.runner.start(target, lambda r: None, errors.append)
        self.assertTrue(_pump(self.runner))
        self.assertEqual(len(errors), 1)
        self.assertIn("RuntimeError", errors[0])
        self.assertIn("rusak", errors[0])

    def test_cancel_forwards_to_token(self):
        cancelled = []
        token = CancellationToken()

        def target(progress_cb, t):
            while True:
                try:
                    t.check()
                except Exception as exc:
                    cancelled.append(type(exc).__name__)
                    raise
                time.sleep(0.01)

        errors = []
        self.runner.start(target, lambda r: None, errors.append,
                          cancel_token=token)
        time.sleep(0.05)
        self.runner.cancel()
        self.assertTrue(_pump(self.runner))
        self.assertEqual(cancelled, ["CancelledError"])
        self.assertIn("CancelledError", errors[0])

    def test_poll_after_window_destroyed_does_not_raise(self):
        started = threading.Event()
        release = threading.Event()

        def target(progress_cb, token):
            started.set()
            release.wait(5)
            return "ok"

        self.runner.start(target, lambda r: None, lambda m: None)
        self.assertTrue(started.wait(5))
        self.root.destroy()
        self.runner._poll()  # tidak boleh raise setelah jendela ditutup
        release.set()
        deadline = time.monotonic() + 5
        while self.runner.busy and time.monotonic() < deadline:
            self.runner._poll()
            time.sleep(0.01)
        self.runner.wait(2.0)
        self.assertFalse(self.runner.busy)

    def test_shutdown_stops_polling_and_cancels_pending_after(self):
        started = threading.Event()
        release = threading.Event()

        def target(progress_cb, token):
            started.set()
            release.wait(5)
            return "ok"

        self.runner.start(target, lambda r: None, lambda m: None)
        self.assertTrue(started.wait(5))
        self.runner.shutdown()
        self.assertFalse(self.runner.busy)
        self.assertIsNone(self.runner._after_id)
        self.root.update()  # tidak boleh ada callback after tertunda
        self.runner._poll()  # tidak boleh re-arm setelah shutdown
        self.assertIsNone(self.runner._after_id)
        release.set()
        self.runner.wait(2.0)


class ExportsTest(unittest.TestCase):
    def test_json_roundtrip_preserves_types_and_utf8(self):
        result = {
            "target": "café.example",
            "scan_type": "ip_lookup",
            "nilai": ["réseau", 1.25, None, True],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hasil.json")
            write_json_result(path, result)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), result)
            with open(path, encoding="utf-8") as fh:
                self.assertIn("café.example", fh.read())

    def test_csv_writes_header_and_port_rows(self):
        result = {
            "scan_type": "tcp_connect",
            "ports": [
                {"port": 80, "status": "open", "duration_ms": 1.2, "error": None},
                {"port": 443, "status": "filtered_or_unknown",
                 "duration_ms": 5000.0, "error": "timeout"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "port.csv")
            write_csv_ports(path, result)
            with open(path, encoding="utf-8", newline="") as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[0], CSV_PORT_COLUMNS)
            self.assertEqual(rows[1], ["80", "open", "1.2", ""])
            self.assertEqual(rows[2], ["443", "filtered_or_unknown",
                                       "5000.0", "timeout"])

    def test_csv_rejects_non_port_results(self):
        with self.assertRaises(ValueError):
            port_rows_for_csv({"scan_type": "ip_lookup"})
        with self.assertRaises(ValueError):
            port_rows_for_csv({"scan_type": "tcp_connect"})
        with self.assertRaises(ValueError):
            port_rows_for_csv(None)

    def test_write_errors_propagate(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_dir = os.path.join(tmp, "tidak-ada", "x.json")
            with self.assertRaises(OSError):
                write_json_result(missing_dir, {"scan_type": "ip_lookup"})
            with self.assertRaises(OSError):
                write_csv_ports(missing_dir, {"scan_type": "tcp_connect",
                                              "ports": []})


class ExportDialogTest(_TkTestCase):
    def test_json_export_writes_file_via_dialog(self):
        result = {"scan_type": "tcp_connect", "target": "127.0.0.1",
                  "ports": [{"port": 80, "status": "open"}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "hasil.json")
            with mock.patch("gui.scan_tabs.filedialog.asksaveasfilename",
                            return_value=path):
                self.assertTrue(export_result(self.root, result, "json"))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["scan_type"], "tcp_connect")

    def test_dialog_cancel_creates_no_file(self):
        result = {"scan_type": "tcp_connect", "target": "127.0.0.1",
                  "ports": []}
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("gui.scan_tabs.filedialog.asksaveasfilename",
                            return_value=""):
                self.assertFalse(export_result(self.root, result, "json"))
            self.assertEqual(os.listdir(tmp), [])

    def test_csv_export_rejects_non_port_without_dialog(self):
        with mock.patch("gui.scan_tabs.filedialog.asksaveasfilename") as ask, \
                mock.patch("gui.scan_tabs.messagebox.showinfo") as info:
            self.assertFalse(export_result(
                self.root, {"scan_type": "ip_lookup", "target": "x"}, "csv"))
        ask.assert_not_called()
        info.assert_called_once()


class ScanTabHelpersTest(unittest.TestCase):
    def test_label_port_status(self):
        self.assertEqual(label_port_status("open"), "Terbuka")
        self.assertEqual(label_port_status("closed"), "Tertutup")
        self.assertEqual(label_port_status("filtered_or_unknown"), "Tidak pasti")
        self.assertEqual(label_port_status("aneh"), "aneh")

    def test_label_scan_status(self):
        self.assertEqual(label_scan_status("completed"), "Selesai")
        self.assertEqual(label_scan_status("cancelled"), "Dibatalkan")
        self.assertEqual(label_scan_status("failed"), "Gagal")

    def test_label_scan_type(self):
        self.assertEqual(label_scan_type("tcp_connect"), "Port Scanner")
        self.assertEqual(label_scan_type("ip_lookup"), "IP Lookup")
        self.assertEqual(label_scan_type(None), "-")

    def test_format_timestamp(self):
        self.assertEqual(format_timestamp("2026-10-26T11:30:00.123456"),
                         "2026-10-26 11:30:00")
        self.assertEqual(format_timestamp(None), "-")
        self.assertEqual(format_timestamp(""), "-")
        self.assertEqual(format_timestamp("bukan-tanggal"), "bukan-tanggal")

    def test_format_summary(self):
        self.assertEqual(
            format_summary({"scan_type": "tcp_connect", "ports": [{"port": 80}],
                            "summary": {"open": 1, "skipped": 2}}),
            "3 port · 1 terbuka")
        self.assertEqual(
            format_summary({"scan_type": "ip_lookup", "ipv4": ["1.2.3.4"],
                            "ipv6": []}),
            "1 alamat IPv4, 0 alamat IPv6")
        self.assertEqual(
            format_summary({"scan_type": "dns_lookup",
                            "records": {"A": ["1.1.1.1"], "MX": ["10 mail.x"]}}),
            "2 record DNS")
        self.assertEqual(
            format_summary({"scan_type": "whois_lookup", "raw_response": "abc"}),
            "3 karakter WHOIS")
        self.assertEqual(format_summary(None), "-")

    def test_format_summary_failed_results_show_dash(self):
        for scan_type in ("tcp_connect", "ip_lookup", "dns_lookup",
                          "whois_lookup"):
            self.assertEqual(
                format_summary({"scan_type": scan_type, "error": "x"}), "-")
        self.assertEqual(
            format_summary({"scan_type": "whois_lookup", "error": "e",
                            "raw_response": "ab"}),
            "2 karakter WHOIS")

    def test_format_duration(self):
        self.assertEqual(format_duration(2.0), "2.0")
        self.assertEqual(format_duration(None), "0.0")
        self.assertEqual(format_duration("abc"), "-")


class SortKeyTest(unittest.TestCase):
    def test_numbers_sort_numerically(self):
        self.assertLess(sort_key(9), sort_key(10))

    def test_text_case_insensitive(self):
        self.assertEqual(sorted(["b", "B", "a"], key=sort_key), ["a", "B", "b"])
        self.assertLess(sort_key("A"), sort_key("b"))

    def test_none_sorts_like_empty_text(self):
        self.assertEqual(sort_key(None), sort_key(""))

    def test_mixed_types_comparable_without_error(self):
        sorted([sort_key(v) for v in [10, "2", None, 3.5, "a", True]])


class SortableTableTest(_TkTestCase):
    def setUp(self):
        super().setUp()
        self.table = SortableTable(self.root, ["angka", "teks"],
                                   headings=["Angka", "Teks"])
        self.table.pack()

    def test_click_header_sorts_and_preserves_ids(self):
        self.table.set_rows([("10", "b"), (2, "a"), ("1", "c")],
                            ids=["x", "y", "z"])
        self.table._sort_by("angka")
        self.assertEqual(self.table.get_values(),
                         [(2, "a"), ("1", "c"), ("10", "b")])
        self.table._sort_by("angka")
        self.assertEqual(self.table.get_values(),
                         [("10", "b"), ("1", "c"), (2, "a")])
        first_item = self.table.tree.get_children()[0]
        self.table.tree.selection_set(first_item)
        self.assertEqual(self.table.selected_id(), "x")

    def test_set_rows_keeps_insertion_order_until_sorted(self):
        self.table.set_rows([(3,), (1,), (2,)])
        self.assertEqual(self.table.get_values(), [(3,), (1,), (2,)])


class PortScannerTabTest(_TkTestCase):
    def _make_tab(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config = Config(os.path.join(tmp.name, "config.json"))
        runner = TaskRunner(self.root)
        target_var = tk.StringVar(value="127.0.0.1")
        statuses, results = [], []
        tab = PortScannerTab(self.root, config, runner, target_var,
                             statuses.append,
                             lambda r, s: results.append((r, s)))
        return tab, runner, results, statuses

    def test_custom_entry_follows_preset(self):
        tab, _runner, _results, _statuses = self._make_tab()
        tab.preset_var.set("Kustom")
        tab._sync_custom_entry()
        self.assertEqual(str(tab.custom_entry["state"]), "normal")
        tab.preset_var.set("Umum")
        tab._sync_custom_entry()
        self.assertEqual(str(tab.custom_entry["state"]), "disabled")

    def test_invalid_custom_ports_shows_error_and_does_not_start(self):
        tab, runner, results, _statuses = self._make_tab()
        tab.preset_var.set("Kustom")
        tab.custom_var.set("abc")
        with mock.patch("gui.scan_tabs.messagebox.showerror") as showerror:
            tab.start()
            showerror.assert_called_once()
        self.assertFalse(runner.busy)
        self.assertEqual(results, [])

    def test_out_of_range_timeout_and_workers_rejected(self):
        tab, runner, results, _statuses = self._make_tab()
        tab.timeout_var.set("0.1")
        with mock.patch("gui.scan_tabs.messagebox.showerror") as showerror:
            tab.start()
            showerror.assert_called_once()
        self.assertFalse(runner.busy)
        tab.timeout_var.set("60.5")
        with mock.patch("gui.scan_tabs.messagebox.showerror") as showerror:
            tab.start()
            showerror.assert_called_once()
        self.assertFalse(runner.busy)
        tab.timeout_var.set("5")
        tab.workers_var.set("999")
        with mock.patch("gui.scan_tabs.messagebox.showerror") as showerror:
            tab.start()
            showerror.assert_called_once()
        self.assertFalse(runner.busy)
        self.assertEqual(results, [])


class HistoryTabTest(_TkTestCase):
    def _make_db(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return DatabaseManager(os.path.join(tmp.name, "scans.db"))

    def _make_tab(self, db):
        return HistoryTab(self.root, db, lambda s: None)

    def test_empty_db_shows_placeholder(self):
        tab = self._make_tab(self._make_db())
        self.assertEqual(tab.table.get_values(), [])
        self.assertEqual(tab.empty_label.winfo_manager(), "grid")

    def test_refresh_renders_rows_and_hides_placeholder(self):
        db = self._make_db()
        db.save_scan_session("example.com", "dns_lookup",
                             {"scan_type": "dns_lookup",
                              "records": {"A": ["1.1.1.1"]}},
                             status="completed")
        tab = self._make_tab(db)
        rows = tab.table.get_values()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "example.com")
        self.assertEqual(rows[0][2], "DNS Lookup")
        self.assertEqual(rows[0][3], "Selesai")
        self.assertEqual(rows[0][5], "1 record DNS")
        self.assertEqual(tab.empty_label.winfo_manager(), "")

    def test_delete_selected_removes_row(self):
        db = self._make_db()
        db.save_scan_session("example.com", "ip_lookup",
                             {"scan_type": "ip_lookup"}, status="completed")
        tab = self._make_tab(db)
        first_item = tab.table.tree.get_children()[0]
        tab.table.tree.selection_set(first_item)
        with mock.patch("gui.scan_tabs.messagebox.askyesno",
                        return_value=True):
            tab._delete_selected()
        self.assertEqual(tab.table.get_values(), [])
        self.assertEqual(db.get_scan_history(), [])

    def test_refresh_survives_corrupt_duration(self):
        db = self._make_db()
        conn = sqlite3.connect(db.db_path)
        try:
            conn.execute(
                "INSERT INTO scan_sessions (target, scan_type, timestamp, "
                "results, risk_score, status, duration) VALUES (?, ?, ?, ?, "
                "?, ?, ?)",
                ("corrupt.example", "ip_lookup", "2026-10-26T10:00:00",
                 json.dumps({"scan_type": "ip_lookup",
                             "ipv4": ["1.2.3.4"]}),
                 0, "completed", "abc"))
            conn.commit()
        finally:
            conn.close()
        tab = self._make_tab(db)
        rows = tab.table.get_values()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][4], "-")
        self.assertEqual(rows[0][5], "1 alamat IPv4, 0 alamat IPv6")


class SettingsDialogTest(_TkTestCase):
    def test_save_persists_valid_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            config = Config(config_path)
            dialog = SettingsDialog(self.root, config)
            dialog.timeout_var.set("7.5")
            dialog.workers_var.set("25")
            dialog.rate_var.set("20")
            dialog.rate_limiting_var.set(False)
            dialog._save()
            self.assertEqual(config.get("scan_settings.timeout"), 7.5)
            self.assertEqual(config.get("scan_settings.max_threads"), 25)
            self.assertEqual(config.get("scan_settings.rate_limit"), 20)
            self.assertFalse(config.get("security.rate_limiting"))
            reloaded = Config(config_path)
            self.assertEqual(reloaded.get("scan_settings.timeout"), 7.5)
            self.assertEqual(reloaded.get("security.rate_limiting"), False)

    def test_invalid_values_rejected_without_saving(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            config = Config(config_path)
            dialog = SettingsDialog(self.root, config)
            dialog.timeout_var.set("abc")
            with mock.patch("gui.settings_dialog.messagebox.showerror") as err:
                dialog._save()
                err.assert_called_once()
            self.assertEqual(config.get("scan_settings.timeout"), 5)
            dialog.timeout_var.set("0.1")
            with mock.patch("gui.settings_dialog.messagebox.showerror") as err:
                dialog._save()
                err.assert_called_once()
            self.assertEqual(config.get("scan_settings.timeout"), 5)


class MainWindowSmokeTest(unittest.TestCase):
    def _make_window(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        win = MainWindow(config_path=os.path.join(tmp.name, "config.json"),
                         db_path=os.path.join(tmp.name, "scans.db"))
        self.addCleanup(self._destroy, win)
        win.root.withdraw()
        return win

    @staticmethod
    def _destroy(win):
        try:
            win.root.update()  # flush event idle agar destroy bersih
            win.root.destroy()
        except tk.TclError:
            pass

    def test_window_builds_five_tabs_and_shared_target(self):
        win = self._make_window()
        win.root.update_idletasks()
        tabs = [win.notebook.tab(t, "text") for t in win.notebook.tabs()]
        self.assertEqual(tabs, ["IP Lookup", "DNS Lookup", "WHOIS Lookup",
                                "Port Scanner", "Riwayat"])
        win.target_var.set("127.0.0.1")
        self.assertEqual(win.target_entry.get(), "127.0.0.1")
        self.assertEqual(win.status_var.get(), "Siap.")

    def test_starts_with_corrupt_config_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        config_path = os.path.join(tmp.name, "config.json")
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write("{ ini bukan json")
        win = MainWindow(config_path=config_path,
                         db_path=os.path.join(tmp.name, "scans.db"))
        self.addCleanup(self._destroy, win)
        win.root.withdraw()
        self.assertEqual(win.config.get("scan_settings.timeout"), 5)
        self.assertEqual(win.status_var.get(), "Siap.")

    def test_close_asks_confirmation_while_busy(self):
        win = self._make_window()
        win.root.update_idletasks()  # flush event idle agar destroy bersih
        started = threading.Event()
        token = CancellationToken()

        def target(progress_cb, _token):
            started.set()
            while not token.is_cancelled():
                time.sleep(0.01)

        win.runner.start(target, lambda r: None, lambda m: None,
                         cancel_token=token)
        self.assertTrue(started.wait(5))
        with mock.patch("gui.main_window.messagebox.askyesno",
                        return_value=False):
            win._on_close()
        self.assertTrue(win.root.winfo_exists())  # jendela masih hidup
        with mock.patch("gui.main_window.messagebox.askyesno",
                        return_value=True):
            win._on_close()
        try:
            win.root.winfo_exists()
            destroyed = False
        except tk.TclError:
            destroyed = True
        self.assertTrue(destroyed)


class DefaultDataDirTest(unittest.TestCase):
    def test_source_mode_returns_project_root(self):
        with mock.patch.object(sys, "frozen", False, create=True):
            self.assertEqual(_default_data_dir(), PROJECT_ROOT)

    def test_frozen_mode_uses_localappdata_and_creates_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        expected = os.path.join(tmp.name, "OSINT Port Scanner")
        with mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp.name}):
            self.assertEqual(_default_data_dir(), expected)
        self.assertTrue(os.path.isdir(expected))

    def test_frozen_mode_without_localappdata_falls_back_to_home(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        expected = os.path.join(tmp.name, "OSINT Port Scanner")
        with mock.patch.object(sys, "frozen", True, create=True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": ""}), \
                mock.patch("gui.main_window.os.path.expanduser",
                           return_value=tmp.name):
            self.assertEqual(_default_data_dir(), expected)
        self.assertTrue(os.path.isdir(expected))


class PortScanEndToEndTest(unittest.TestCase):
    def test_localhost_scan_shows_open_row_and_saves_history(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        win = MainWindow(config_path=os.path.join(tmp.name, "config.json"),
                         db_path=os.path.join(tmp.name, "scans.db"))
        win.root.withdraw()
        listener = _EphemeralListener()
        self.addCleanup(listener.close)
        try:
            win.target_var.set("127.0.0.1")
            win.port_tab.preset_var.set("Kustom")
            win.port_tab._sync_custom_entry()
            win.port_tab.custom_var.set(str(listener.port))
            win.port_tab.start()
            self.assertTrue(_pump(win.runner, timeout=15))
            rows = win.port_tab.table.get_values()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], "Terbuka")
            self.assertIn("Terbuka: 1", win.port_tab.summary_var.get())
            history = win.db.get_scan_history()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0][2], "tcp_connect")
            self.assertEqual(history[0][6], "completed")
        finally:
            try:
                win.root.update_idletasks()  # flush event idle agar destroy bersih
                win.root.destroy()
            except tk.TclError:
                pass

    def test_cancel_via_button_marks_cancelled(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        win = MainWindow(config_path=os.path.join(tmp.name, "config.json"),
                         db_path=os.path.join(tmp.name, "scans.db"))
        win.root.withdraw()
        fake = {
            "target": "127.0.0.1",
            "target_ip": "127.0.0.1",
            "scan_type": "tcp_connect",
            "ports": [],
            "tcp_ports": [],
            "summary": {"open": 0, "closed": 0,
                        "filtered_or_unknown": 0, "skipped": 2},
            "cancelled": True,
            "duration": 0.01,
        }

        def fake_scan(target, ports, **kwargs):
            token = kwargs["cancel_token"]
            while not token.is_cancelled():
                time.sleep(0.01)
            return fake

        try:
            win.target_var.set("127.0.0.1")
            win.port_tab.preset_var.set("Kustom")
            win.port_tab._sync_custom_entry()
            win.port_tab.custom_var.set("80, 443")
            with mock.patch("gui.scan_tabs.scan_tcp_ports",
                            side_effect=fake_scan):
                win.port_tab.start()
                time.sleep(0.05)
                win.port_tab.cancel()
                self.assertTrue(_pump(win.runner, timeout=15))
            self.assertEqual(win.port_tab.table.get_values(), [])
            self.assertIn("Dilewati: 2", win.port_tab.summary_var.get())
            history = win.db.get_scan_history()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0][6], "cancelled")
        finally:
            try:
                win.root.update_idletasks()  # flush event idle agar destroy bersih
                win.root.destroy()
            except tk.TclError:
                pass

    def test_close_during_scan_saves_cancelled_history(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        win = MainWindow(config_path=os.path.join(tmp.name, "config.json"),
                         db_path=os.path.join(tmp.name, "scans.db"))
        win.root.withdraw()
        fake = {
            "target": "127.0.0.1",
            "target_ip": "127.0.0.1",
            "scan_type": "tcp_connect",
            "ports": [],
            "tcp_ports": [],
            "summary": {"open": 0, "closed": 0,
                        "filtered_or_unknown": 0, "skipped": 2},
            "cancelled": True,
            "duration": 0.01,
        }

        def fake_scan(target, ports, **kwargs):
            token = kwargs["cancel_token"]
            while not token.is_cancelled():
                time.sleep(0.01)
            return fake

        try:
            win.target_var.set("127.0.0.1")
            win.port_tab.preset_var.set("Kustom")
            win.port_tab._sync_custom_entry()
            win.port_tab.custom_var.set("80, 443")
            with mock.patch("gui.scan_tabs.scan_tcp_ports",
                            side_effect=fake_scan):
                win.port_tab.start()
                time.sleep(0.05)
                with mock.patch("gui.main_window.messagebox.askyesno",
                                return_value=True):
                    win._on_close()
            history = win.db.get_scan_history()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0][6], "cancelled")
            try:
                win.root.winfo_exists()
                destroyed = False
            except tk.TclError:
                destroyed = True
            self.assertTrue(destroyed)
        finally:
            try:
                win.root.update_idletasks()  # flush event idle agar destroy bersih
                win.root.destroy()
            except tk.TclError:
                pass


if __name__ == "__main__":
    unittest.main()
