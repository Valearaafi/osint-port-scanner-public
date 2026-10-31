import socket
import unittest
from unittest import mock

from scanner.reconnaissance import whois_enhanced
from scanner.reconnaissance.whois_enhanced import IANA_SERVER, WhoisError


class _FakeSocket:
    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.sent = []

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _patch_connections(sockets):
    return mock.patch(
        "scanner.reconnaissance.whois_enhanced.socket.create_connection",
        side_effect=sockets,
    )


IANA_TEXT = (
    "% IANA WHOIS server\n"
    "domain:       EXAMPLE\n"
    "refer:        whois.example-registry.net\n"
)
REGISTRY_TEXT = "Domain Name: EXAMPLE.COM\r\nRegistrar: Example Registrar\r\n"


class TestWhoisLookup(unittest.TestCase):
    def test_full_flow_with_referral(self):
        sockets = [
            _FakeSocket([IANA_TEXT.encode()]),
            _FakeSocket([REGISTRY_TEXT.encode()]),
        ]
        with _patch_connections(sockets):
            result = whois_enhanced.whois_lookup("example.com")

        self.assertIsNone(result["error"])
        self.assertEqual(result["server"], "whois.example-registry.net")
        self.assertIn("Registrar", result["raw_response"])
        self.assertEqual(sockets[0].sent[0], b"example.com\r\n")
        self.assertEqual(sockets[1].sent[0], b"example.com\r\n")

    def test_timeout_raises_clear_error(self):
        with mock.patch(
            "scanner.reconnaissance.whois_enhanced.socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            with self.assertRaises(WhoisError) as ctx:
                whois_enhanced.whois_lookup("example.com", timeout=3.0)
        self.assertIn("timeout", str(ctx.exception))

    def test_connection_refused_raises_clear_error(self):
        with mock.patch(
            "scanner.reconnaissance.whois_enhanced.socket.create_connection",
            side_effect=ConnectionRefusedError(10061, "Connection refused"),
        ):
            with self.assertRaises(WhoisError) as ctx:
                whois_enhanced.whois_lookup("example.com")
        self.assertIn("gagal", str(ctx.exception))

    def test_no_referral_from_iana(self):
        sockets = [_FakeSocket([b"% IANA WHOIS server\nno referral here\n"])]
        with _patch_connections(sockets):
            result = whois_enhanced.whois_lookup("example.com")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["server"], IANA_SERVER)

    def test_empty_registry_response(self):
        sockets = [
            _FakeSocket([IANA_TEXT.encode()]),
            _FakeSocket([b""]),
        ]
        with _patch_connections(sockets):
            result = whois_enhanced.whois_lookup("example.com")
        self.assertIsNotNone(result["error"])
        self.assertIn("kosong", result["error"])

    def test_invalid_domains(self):
        for bad in ("", "   ", "foo bar", "nodot", "http://example.com/x"):
            with self.assertRaises(WhoisError):
                whois_enhanced.whois_lookup(bad)


if __name__ == "__main__":
    unittest.main()
