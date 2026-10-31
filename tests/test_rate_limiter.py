import time
import unittest

from scanner.utils.rate_limiter import RateLimiter, create_rate_limiter


class TestRateLimiter(unittest.TestCase):
    def test_disabled_has_no_delay(self):
        limiter = RateLimiter(0.0)
        start = time.monotonic()
        for _ in range(20):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.2)

    def test_enforced_minimum_duration(self):
        limiter = RateLimiter(5.0)  # interval minimum 0.2 detik
        start = time.monotonic()
        for _ in range(3):
            limiter.wait()
        # ambang 0.35: toleran terhadap granularitas timer Windows (~15 ms)
        self.assertGreaterEqual(time.monotonic() - start, 0.35)

    def test_set_rate(self):
        limiter = RateLimiter(1000.0)
        start = time.monotonic()
        for _ in range(50):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.5)

        limiter.set_rate(0.0)
        start = time.monotonic()
        for _ in range(50):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.2)


class _FakeConfig:
    def __init__(self, values):
        self._values = values

    def get(self, key, default=None):
        return self._values[key]


class TestCreateRateLimiter(unittest.TestCase):
    def test_enabled_from_config(self):
        config = _FakeConfig(
            {"security.rate_limiting": True, "scan_settings.rate_limit": 10}
        )
        self.assertGreater(create_rate_limiter(config)._min_interval, 0)

    def test_disabled_from_config(self):
        config = _FakeConfig(
            {"security.rate_limiting": False, "scan_settings.rate_limit": 10}
        )
        self.assertEqual(create_rate_limiter(config)._min_interval, 0.0)


if __name__ == "__main__":
    unittest.main()
