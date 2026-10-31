import unittest
from unittest import mock

import dns.resolver

from scanner.reconnaissance import dns_enum


class _FakeAnswer:
    def __init__(self, text):
        self._text = text

    def __str__(self):
        return self._text


class _FakeMX:
    def __init__(self, preference, exchange):
        self.preference = preference
        self.exchange = _FakeAnswer(exchange)


class TestLookupRecords(unittest.TestCase):
    def test_success_all_types(self):
        responses = {
            "A": [_FakeAnswer("192.0.2.1"), _FakeAnswer("192.0.2.2")],
            "AAAA": [_FakeAnswer("2001:db8::1")],
            "NS": [_FakeAnswer("ns1.example.com."), _FakeAnswer("ns2.example.com.")],
            "MX": [_FakeMX(20, "mail2.example.com."), _FakeMX(10, "mail1.example.com.")],
        }

        def fake_resolve(domain, rtype, lifetime=None):
            return responses[rtype]

        with mock.patch.object(dns.resolver, "resolve", side_effect=fake_resolve):
            result = dns_enum.lookup_records("example.com", timeout=2.0)

        self.assertEqual(result["errors"], {})
        self.assertEqual(result["records"]["A"], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(result["records"]["AAAA"], ["2001:db8::1"])
        self.assertEqual(
            result["records"]["NS"], ["ns1.example.com", "ns2.example.com"]
        )
        self.assertEqual(
            result["records"]["MX"],
            ["10 mail1.example.com", "20 mail2.example.com"],
        )

    def test_nxdomain(self):
        with mock.patch.object(
            dns.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN
        ):
            result = dns_enum.lookup_records("nonexistent.example")
        self.assertEqual(result["records"], {})
        self.assertIn("A", result["errors"])
        self.assertIn("NXDOMAIN", result["errors"]["A"])

    def test_no_answer(self):
        with mock.patch.object(
            dns.resolver, "resolve", side_effect=dns.resolver.NoAnswer
        ):
            result = dns_enum.lookup_records("example.com", ("MX",))
        self.assertIn("MX", result["errors"])
        self.assertNotIn("MX", result["records"])

    def test_timeout(self):
        with mock.patch.object(
            dns.resolver, "resolve", side_effect=dns.resolver.Timeout
        ):
            result = dns_enum.lookup_records("example.com", ("A",))
        self.assertIn("A", result["errors"])

    def test_no_nameservers(self):
        with mock.patch.object(
            dns.resolver, "resolve", side_effect=dns.resolver.NoNameservers
        ):
            result = dns_enum.lookup_records("example.com", ("A",))
        self.assertIn("A", result["errors"])

    def test_unsupported_type(self):
        result = dns_enum.lookup_records("example.com", ("TXT",))
        self.assertIn("TXT", result["errors"])
        self.assertIn("tidak didukung", result["errors"]["TXT"])

    def test_empty_domain(self):
        with self.assertRaises(ValueError):
            dns_enum.lookup_records("")


if __name__ == "__main__":
    unittest.main()
