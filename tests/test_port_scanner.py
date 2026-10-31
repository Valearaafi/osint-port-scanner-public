import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from config.settings import Config

from scanner.network import port_scanner
from scanner.network.port_scanner import (
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_OPEN,
    parse_port_list,
    resolve_port_list,
    scan_tcp_ports,
)
from scanner.utils.ip_utils import ResolutionError
from scanner.utils.threading_manager import CancellationToken


class _EphemeralListener:
    """Listener TCP sementara di 127.0.0.1 — dijamin ditutup setelah tes."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
                conn.close()
            except OSError:
                return

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


def _ephemeral_closed_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestParsePortList(unittest.TestCase):
    def test_valid_inputs(self):
        self.assertEqual(parse_port_list("80,443"), [80, 443])
        self.assertEqual(parse_port_list("80 443"), [80, 443])
        self.assertEqual(parse_port_list("8000-8002"), [8000, 8001, 8002])
        self.assertEqual(
            parse_port_list("80, 443, 8000-8002"), [80, 443, 8000, 8001, 8002]
        )

    def test_dedupe_and_sort(self):
        self.assertEqual(parse_port_list("80,80,443,80"), [80, 443])
        self.assertEqual(parse_port_list("8080,80"), [80, 8080])

    def test_invalid_inputs(self):
        for bad in ("", "   ", "abc", "0", "65536", "1-65536", "100-50", "80-"):
            with self.assertRaises(ValueError):
                parse_port_list(bad)


class TestResolvePortList(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.config = Config(os.path.join(self._tmp.name, "config.json"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_common_preset(self):
        ports = resolve_port_list(self.config, "common")
        self.assertEqual(len(ports), 20)
        self.assertEqual(ports[:2], [21, 22])

    def test_extended_preset(self):
        ports = resolve_port_list(self.config, "extended")
        self.assertEqual(len(ports), 1024)

    def test_custom_preset(self):
        ports = resolve_port_list(self.config, "custom", "8080-8082")
        self.assertEqual(ports, [8080, 8081, 8082])

    def test_unknown_preset(self):
        with self.assertRaises(ValueError):
            resolve_port_list(self.config, "unknown")


class TestScanOpenPort(unittest.TestCase):
    def test_open_detection_on_localhost(self):
        listener = _EphemeralListener()
        try:
            result = scan_tcp_ports(
                "127.0.0.1", [listener.port], timeout=2.0, max_threads=5
            )
        finally:
            listener.close()

        self.assertFalse(result["cancelled"])
        self.assertEqual(result["ports"][0]["status"], STATUS_OPEN)
        self.assertEqual(result["summary"]["open"], 1)
        self.assertEqual(result["tcp_ports"], [listener.port])


class TestScanClosedPort(unittest.TestCase):
    def test_unreachable_localhost_port_never_reported_open(self):
        """Port loopback tanpa listener: closed ATAU filtered_or_unknown.

        Di Windows loopback, SYN ke port yang tidak mendengarkan sering
        di-drop diam-diam (timeout) alih-alih dijawab RST — karenanya
        klasifikasi yang jujur adalah filtered_or_unknown, bukan closed.
        Klasifikasi closed deterministik diuji via mock (lihat
        TestStatusClassification.test_refused_becomes_closed).
        """
        port = _ephemeral_closed_port()
        result = scan_tcp_ports("127.0.0.1", [port], timeout=1.0, max_threads=5)
        status = result["ports"][0]["status"]
        self.assertIn(status, (STATUS_CLOSED, STATUS_FILTERED))
        if status == STATUS_FILTERED:
            self.assertEqual(result["ports"][0]["error"], "timeout")


class TestStatusClassification(unittest.TestCase):
    def test_timeout_becomes_filtered_not_closed(self):
        with mock.patch(
            "scanner.network.port_scanner.socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            result = scan_tcp_ports("127.0.0.1", [80], timeout=1.0)
        self.assertEqual(result["ports"][0]["status"], STATUS_FILTERED)
        self.assertEqual(result["ports"][0]["error"], "timeout")

    def test_refused_becomes_closed(self):
        with mock.patch(
            "scanner.network.port_scanner.socket.create_connection",
            side_effect=ConnectionRefusedError(10061, "Connection refused"),
        ):
            result = scan_tcp_ports("127.0.0.1", [80], timeout=1.0)
        self.assertEqual(result["ports"][0]["status"], STATUS_CLOSED)

    def test_other_oserror_becomes_filtered_with_message(self):
        with mock.patch(
            "scanner.network.port_scanner.socket.create_connection",
            side_effect=OSError(10065, "No route to host"),
        ):
            result = scan_tcp_ports("127.0.0.1", [80], timeout=1.0)
        self.assertEqual(result["ports"][0]["status"], STATUS_FILTERED)
        self.assertIn("10065", result["ports"][0]["error"])


class TestCancellation(unittest.TestCase):
    def test_cancelled_before_start(self):
        token = CancellationToken()
        token.cancel()
        result = scan_tcp_ports(
            "127.0.0.1", [80, 443], timeout=2.0, cancel_token=token
        )
        self.assertTrue(result["cancelled"])
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["summary"]["skipped"], 2)

    def test_cancelled_mid_scan(self):
        token = CancellationToken()

        def slow_refuse(address, timeout=None):
            time.sleep(0.05)
            raise ConnectionRefusedError(10061, "Connection refused")

        def on_progress(checked, total, last):
            if checked == 5:
                token.cancel()

        with mock.patch(
            "scanner.network.port_scanner.socket.create_connection",
            side_effect=slow_refuse,
        ):
            result = scan_tcp_ports(
                "127.0.0.1",
                list(range(1, 101)),
                timeout=1.0,
                max_threads=10,
                cancel_token=token,
                on_progress=on_progress,
            )

        self.assertTrue(result["cancelled"])
        self.assertLess(len(result["ports"]), 100)
        self.assertGreaterEqual(result["summary"]["skipped"], 1)


class TestConcurrencyBound(unittest.TestCase):
    def test_max_workers_not_exceeded(self):
        lock = threading.Lock()
        state = {"current": 0, "max_seen": 0}

        def tracked(address, timeout=None):
            with lock:
                state["current"] += 1
                state["max_seen"] = max(state["max_seen"], state["current"])
            time.sleep(0.1)
            with lock:
                state["current"] -= 1
            raise ConnectionRefusedError(10061, "Connection refused")

        with mock.patch(
            "scanner.network.port_scanner.socket.create_connection",
            side_effect=tracked,
        ):
            scan_tcp_ports(
                "127.0.0.1", list(range(1, 31)), timeout=2.0, max_threads=5
            )

        self.assertLessEqual(state["max_seen"], 5)
        self.assertGreaterEqual(state["max_seen"], 2)


class TestEmptyAndErrors(unittest.TestCase):
    def test_empty_port_list(self):
        result = scan_tcp_ports("127.0.0.1", [])
        self.assertEqual(result["ports"], [])
        self.assertEqual(result["summary"]["open"], 0)
        self.assertFalse(result["cancelled"])

    def test_progress_callback_called(self):
        port = _ephemeral_closed_port()
        progress = []
        result = scan_tcp_ports(
            "127.0.0.1", [port], timeout=2.0,
            on_progress=lambda checked, total, last: progress.append((checked, total)),
        )
        self.assertEqual(len(progress), 1)
        self.assertEqual(progress[0], (1, 1))
        self.assertEqual(len(result["ports"]), 1)

    def test_resolution_failure_propagates(self):
        with mock.patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            with self.assertRaises(ResolutionError):
                scan_tcp_ports("nonexistent.invalid", [80])


if __name__ == "__main__":
    unittest.main()
