"""Utilitas konkurensi: token pembatalan dan pool thread berbatas."""

import threading
from concurrent.futures import ThreadPoolExecutor


class CancelledError(Exception):
    """Operasi dibatalkan melalui CancellationToken."""


class CancellationToken:
    """Tanda pembatalan kooperatif berbasis threading.Event."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        """Lempar CancelledError bila pembatalan sudah diminta."""
        if self._event.is_set():
            raise CancelledError("Scan dibatalkan.")


class BoundedPool:
    """ThreadPoolExecutor dengan batas worker dan shutdown yang pasti.

    shutdown(wait=True) menjamin tidak ada thread yang dibiarkan berjalan
    tanpa kendali saat konteks keluar; setiap worker dibatasi timeoutnya
    oleh pemanggil (mis. timeout koneksi socket).
    """

    def __init__(self, max_workers: int) -> None:
        self._pool = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))

    def submit(self, fn, *args, **kwargs):
        return self._pool.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)

    def __enter__(self) -> "BoundedPool":
        return self

    def __exit__(self, *exc_info) -> bool:
        self.shutdown(wait=True)
        return False
