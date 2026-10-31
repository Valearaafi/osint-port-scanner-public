"""Rate limiter sederhana berbasis interval antar-operasi. Thread-safe."""

import threading
import time


class RateLimiter:
    """Batasi laju operasi (operasi/detik) secara global antar-thread.

    max_per_second <= 0 berarti tanpa pembatasan (wait() langsung kembali).
    """

    def __init__(self, max_per_second: float = 0.0) -> None:
        self._min_interval = 0.0
        self._lock = threading.Lock()
        self._last = 0.0
        self.set_rate(max_per_second)

    def set_rate(self, max_per_second: float) -> None:
        with self._lock:
            if max_per_second and max_per_second > 0:
                self._min_interval = 1.0 / float(max_per_second)
            else:
                self._min_interval = 0.0

    def wait(self) -> None:
        """Tunggu (bila perlu) hingga slot laju berikutnya tersedia."""
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            next_slot = max(now, self._last + self._min_interval)
            self._last = next_slot
            delay = next_slot - now
        if delay > 0:
            time.sleep(delay)


def create_rate_limiter(config) -> RateLimiter:
    """Buat RateLimiter dari Config: hormati security.rate_limiting."""
    enabled = config.get("security.rate_limiting", True)
    rate = config.get("scan_settings.rate_limit", 0)
    if enabled and rate:
        return RateLimiter(rate)
    return RateLimiter(0.0)
