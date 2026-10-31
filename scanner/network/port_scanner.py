"""TCP connect port scanner.

Pemindaian memakai koneksi TCP biasa (bukan stealth scan) dan TIDAK
melakukan banner grabbing — service atau versi tidak diidentifikasi.
Klasifikasi status:
- open                : koneksi TCP berhasil dibuat.
- closed              : koneksi ditolak secara eksplisit (ECONNREFUSED/ECONNRESET).
- filtered_or_unknown : timeout atau kondisi lain yang tidak cukup untuk
                        menyimpulkan status (port TIDAK diasumsikan tertutup).
"""

import socket
import time
from concurrent.futures import as_completed
from typing import Callable, Dict, List, Optional

from scanner.utils.ip_utils import resolve_target
from scanner.utils.rate_limiter import RateLimiter
from scanner.utils.threading_manager import BoundedPool, CancelledError, CancellationToken

PORT_MIN = 1
PORT_MAX = 65535

STATUS_OPEN = "open"
STATUS_CLOSED = "closed"
STATUS_FILTERED = "filtered_or_unknown"

# Callback(checked: int, total: int, last_result: Optional[dict])
ProgressCallback = Callable[[int, int, Optional[Dict]], None]


def parse_port_list(text: str) -> List[int]:
    """Parse teks port ('80,443' atau '8000-8080') menjadi daftar port valid.

    Mendukung koma/spasi sebagai pemisah dan range dengan tanda hubung.
    Port di luar 1-65535 atau format aneh menghasilkan ValueError.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Daftar port kosong.")

    ports: List[int] = []
    for token in text.replace(",", " ").split():
        if "-" in token:
            try:
                start_text, end_text = token.split("-", 1)
                start, end = int(start_text), int(end_text)
            except ValueError:
                raise ValueError(f"Range port tidak valid: {token!r}.")
            if start > end:
                raise ValueError(f"Range port terbalik: {token!r}.")
            ports.extend(range(start, end + 1))
        else:
            try:
                ports.append(int(token))
            except ValueError:
                raise ValueError(f"Port tidak valid: {token!r}.")

    invalid = [p for p in ports if not (PORT_MIN <= p <= PORT_MAX)]
    if invalid:
        raise ValueError(f"Port di luar rentang {PORT_MIN}-{PORT_MAX}: {invalid[:5]}.")

    return sorted(set(ports))


def resolve_port_list(config, preset: str, custom_text: str = "") -> List[int]:
    """Dapatkan daftar port dari preset konfigurasi atau teks kustom.

    preset: 'common' (common_ports), 'extended' (extended_ports), 'custom'.
    """
    if preset == "custom":
        return parse_port_list(custom_text)
    if preset == "common":
        key = "scan_settings.common_ports"
    elif preset == "extended":
        key = "scan_settings.extended_ports"
    else:
        raise ValueError(f"Preset port tidak dikenal: {preset!r}.")

    ports = config.get(key) or []
    valid = sorted({int(p) for p in ports if PORT_MIN <= int(p) <= PORT_MAX})
    if not valid:
        raise ValueError(f"Preset {preset!r} tidak menghasilkan port yang valid.")
    return valid


def scan_tcp_ports(
    target: str,
    ports: List[int],
    timeout: float = 5.0,
    max_threads: int = 50,
    rate_limiter: Optional[RateLimiter] = None,
    cancel_token: Optional[CancellationToken] = None,
    on_progress: Optional[ProgressCallback] = None,
) -> Dict:
    """Scan TCP connect terhadap daftar port pada target.

    Mengembalikan dict terstruktur:
    {'target', 'target_ip', 'scan_type', 'ports': [{port, status, duration_ms,
    error}], 'tcp_ports': [port open saja], 'summary': {open, closed,
    filtered_or_unknown, skipped}, 'cancelled', 'duration'}.

    Port yang tidak sempat diperiksa karena pembatalan TIDAK dimasukkan ke
    'ports' (tidak ada status yang dibuat-buat) dan dihitung di summary.skipped.
    """
    ports = sorted(set(int(p) for p in ports))
    for port in ports:
        if not (PORT_MIN <= port <= PORT_MAX):
            raise ValueError(f"Port di luar rentang {PORT_MIN}-{PORT_MAX}: {port}.")

    cancel_token = cancel_token or CancellationToken()
    rate_limiter = rate_limiter or RateLimiter(0.0)

    resolved = resolve_target(target)
    connect_ip = resolved["ipv4"][0] if resolved["ipv4"] else resolved["ipv6"][0]

    results: List[Dict] = []
    skipped = 0
    checked = 0
    total = len(ports)
    cancelled = False
    started = time.monotonic()

    def check_port(port: int) -> Dict:
        cancel_token.check()
        rate_limiter.wait()
        cancel_token.check()
        t0 = time.monotonic()
        status = STATUS_FILTERED
        error = None
        try:
            with socket.create_connection((connect_ip, port), timeout=timeout):
                status = STATUS_OPEN
        except (ConnectionRefusedError, ConnectionResetError):
            status = STATUS_CLOSED
        except socket.timeout:
            error = "timeout"
        except OSError as e:
            error = str(e) or e.__class__.__name__
        return {
            "port": port,
            "status": status,
            "duration_ms": round((time.monotonic() - t0) * 1000, 1),
            "error": error,
        }

    with BoundedPool(max_threads) as pool:
        futures = {}
        for port in ports:
            if cancel_token.is_cancelled():
                cancelled = True
                skipped = total - len(futures)
                break
            futures[pool.submit(check_port, port)] = port

        for future in as_completed(futures):
            port = futures[future]
            result: Optional[Dict] = None
            try:
                result = future.result()
            except CancelledError:
                cancelled = True
                skipped += 1
            except Exception as e:
                result = {
                    "port": port,
                    "status": STATUS_FILTERED,
                    "duration_ms": 0.0,
                    "error": str(e),
                }
            checked += 1
            if result is not None:
                results.append(result)
            if on_progress is not None:
                on_progress(checked, total, result)

    open_ports = [r["port"] for r in results if r["status"] == STATUS_OPEN]
    return {
        "target": target,
        "target_ip": connect_ip,
        "scan_type": "tcp_connect",
        "ports": results,
        "tcp_ports": open_ports,
        "summary": {
            "open": sum(1 for r in results if r["status"] == STATUS_OPEN),
            "closed": sum(1 for r in results if r["status"] == STATUS_CLOSED),
            "filtered_or_unknown": sum(1 for r in results if r["status"] == STATUS_FILTERED),
            "skipped": skipped,
        },
        "cancelled": cancelled,
        "duration": round(time.monotonic() - started, 3),
    }
