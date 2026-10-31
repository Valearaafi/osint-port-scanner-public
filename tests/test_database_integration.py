import json
import os
import sqlite3
import tempfile
import unittest

from database import queries
from database.models import DatabaseManager


def _make_result():
    return {
        "target": "127.0.0.1",
        "target_ip": "127.0.0.1",
        "scan_type": "tcp_connect",
        "ports": [
            {"port": 80, "status": "open", "duration_ms": 1.2, "error": None},
            {"port": 81, "status": "closed", "duration_ms": 0.5, "error": None},
        ],
        "tcp_ports": [80],
        "summary": {"open": 1, "closed": 1, "filtered_or_unknown": 0, "skipped": 0},
        "cancelled": False,
        "duration": 0.42,
    }


class TestDatabaseIntegration(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(os.path.join(self._tmp.name, "test.db"))

    def tearDown(self):
        # Koneksi sqlite3 ditutup eksplisit oleh DatabaseManager (conn.close()),
        # sehingga file DB bisa dihapus langsung di Windows.
        self._tmp.cleanup()

    def _host_rows(self, session_id):
        conn = sqlite3.connect(self.db.db_path)
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM discovered_hosts WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
        finally:
            conn.close()

    def test_save_and_load_roundtrip(self):
        result = _make_result()
        session_id = queries.save_scan_session_result(self.db, result)
        row = self.db.get_scan_by_id(session_id)
        self.assertEqual(row[6], "completed")

        loaded = queries.load_scan_session_result(self.db, session_id)
        self.assertEqual(loaded["ports"], result["ports"])
        self.assertEqual(loaded["summary"]["open"], 1)

    def test_open_ports_are_not_vulnerabilities(self):
        queries.save_scan_session_result(self.db, _make_result())
        stats = self.db.get_statistics()
        self.assertEqual(stats["total_vulnerabilities"], 0)

    def test_cancelled_status_distinguishable_and_no_host_row(self):
        result = _make_result()
        result["cancelled"] = True
        session_id = queries.save_scan_session_result(
            self.db, result, status="cancelled"
        )
        row = self.db.get_scan_by_id(session_id)
        self.assertEqual(row[6], "cancelled")
        self.assertEqual(self._host_rows(session_id), 0)

    def test_failed_status_distinguishable(self):
        result = {
            "target": "example.com",
            "scan_type": "tcp_connect",
            "error": "resolusi gagal",
        }
        session_id = queries.save_scan_session_result(self.db, result, status="failed")
        row = self.db.get_scan_by_id(session_id)
        self.assertEqual(row[6], "failed")
        self.assertEqual(self._host_rows(session_id), 0)

    def test_completed_saves_host_row_with_open_ports(self):
        session_id = queries.save_scan_session_result(self.db, _make_result())
        self.assertEqual(self._host_rows(session_id), 1)
        conn = sqlite3.connect(self.db.db_path)
        try:
            open_ports = conn.execute(
                "SELECT open_ports FROM discovered_hosts WHERE session_id = ?",
                (session_id,),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(json.loads(open_ports), [80])

    def test_load_missing_session_returns_none(self):
        self.assertIsNone(queries.load_scan_session_result(self.db, 9999))


if __name__ == "__main__":
    unittest.main()
