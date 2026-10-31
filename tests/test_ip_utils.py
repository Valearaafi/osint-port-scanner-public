import socket
import unittest
from unittest import mock

from scanner.utils import ip_utils
from scanner.utils.ip_utils import InvalidTargetError, ResolutionError


class TestValidateTarget(unittest.TestCase):
    def test_empty_input(self):
        for bad in ("", "   ", None):
            with self.assertRaises(InvalidTargetError):
                ip_utils.validate_target(bad)

    def test_ipv4(self):
        self.assertEqual(ip_utils.validate_target("127.0.0.1"), "ipv4")
        self.assertEqual(ip_utils.validate_target(" 192.168.1.1 "), "ipv4")

    def test_ipv6(self):
        self.assertEqual(ip_utils.validate_target("::1"), "ipv6")
        self.assertEqual(ip_utils.validate_target("2001:db8::1"), "ipv6")

    def test_hostname(self):
        self.assertEqual(ip_utils.validate_target("localhost"), "hostname")
        self.assertEqual(ip_utils.validate_target("example.com"), "hostname")
        self.assertEqual(ip_utils.validate_target("sub.domain.co.id"), "hostname")

    def test_invalid_formats(self):
        for bad in (
            "999.999.999.999",
            "example..com",
            "-bad.com",
            "bad-.com",
            "a" * 64 + ".com",
            "http://example.com",
            "foo bar",
        ):
            with self.assertRaises(InvalidTargetError):
                ip_utils.validate_target(bad)


class TestResolveHostname(unittest.TestCase):
    def test_localhost_real_resolution(self):
        result = ip_utils.resolve_hostname("localhost")
        self.assertIn("127.0.0.1", result["ipv4"])

    def test_empty_hostname(self):
        with self.assertRaises(ResolutionError):
            ip_utils.resolve_hostname("")

    def test_resolution_failure(self):
        with mock.patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            with self.assertRaises(ResolutionError):
                ip_utils.resolve_hostname("nonexistent.invalid")


class TestResolveTarget(unittest.TestCase):
    def test_ip_passthrough(self):
        self.assertEqual(ip_utils.resolve_target("10.0.0.1")["ipv4"], ["10.0.0.1"])
        self.assertEqual(ip_utils.resolve_target("::1")["ipv6"], ["::1"])

    def test_hostname_resolution(self):
        result = ip_utils.resolve_target("localhost")
        self.assertEqual(result["kind"], "hostname")
        self.assertIn("127.0.0.1", result["ipv4"])


if __name__ == "__main__":
    unittest.main()
