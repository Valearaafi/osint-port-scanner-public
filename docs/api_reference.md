# Referensi API — OSINT Port Scanner

Ringkasan fungsi publik modul yang terimplementasi (v0.3.0). Hanya modul
yang tercantum di bawah ini yang tersedia di repositori; tidak ada modul
tersembunyi atau API lain di luar daftar ini.

## scanner.utils.ip_utils

```python
class InvalidTargetError(ValueError)   # target kosong/format tidak valid
class ResolutionError(Exception)       # resolusi DNS gagal

validate_target(target: str) -> str
# 'ipv4' | 'ipv6' | 'hostname'; lempar InvalidTargetError bila tidak valid.
# Valid berarti format dapat diproses — bukan jaminan host aman/terjangkau.

resolve_hostname(hostname: str) -> Dict[str, List[str]]
# {'ipv4': [...], 'ipv6': [...]} via resolver sistem; ResolutionError
# bila tidak ada alamat — tidak ada hasil yang dibuat-buat.

resolve_target(target: str) -> Dict[str, object]
# {'kind', 'target', 'ipv4', 'ipv6'} (+ 'hostname' untuk hostname).
```

## scanner.utils.threading_manager

```python
class CancelledError(Exception)

class CancellationToken:
    cancel() -> None          # minta pembatalan (threading.Event)
    is_cancelled() -> bool
    check() -> None           # lempar CancelledError bila dibatalkan

class BoundedPool:            # ThreadPoolExecutor dengan shutdown pasti
    submit(fn, *args, **kwargs)
    shutdown(wait: bool = True)
```

## scanner.utils.rate_limiter

```python
class RateLimiter:
    __init__(max_per_second: float = 0.0)   # <=0 = tanpa batas; thread-safe
    set_rate(max_per_second: float)
    wait() -> None                          # tahan hingga slot laju tersedia

create_rate_limiter(config) -> RateLimiter
# Hormati security.rate_limiting + scan_settings.rate_limit dari Config.
```

## scanner.network.port_scanner

```python
STATUS_OPEN = "open"; STATUS_CLOSED = "closed"
STATUS_FILTERED = "filtered_or_unknown"

parse_port_list(text: str) -> List[int]
# '80,443' / '8000-8080'; ValueError untuk format/rentang tidak valid;
# hasil terurut tanpa duplikat.

resolve_port_list(config, preset: str, custom_text: str = "") -> List[int]
# preset: 'common' | 'extended' | 'custom' (custom membaca custom_text).

scan_tcp_ports(target, ports, timeout=5.0, max_threads=50,
               rate_limiter=None, cancel_token=None, on_progress=None) -> Dict
# {'target', 'target_ip', 'scan_type', 'ports': [{port, status, duration_ms,
# error}], 'tcp_ports': [port terbuka], 'summary': {open, closed,
# filtered_or_unknown, skipped}, 'cancelled', 'duration'}.
# on_progress(checked, total, last_result_or_None). Port yang dilewati
# karena pembatalan TIDAK difabrikasi statusnya.
```

## scanner.reconnaissance.dns_enum

```python
SUPPORTED_TYPES = ("A", "AAAA", "NS", "MX")

lookup_records(domain, record_types=SUPPORTED_TYPES, timeout=5.0) -> Dict
# {'domain', 'records': {tipe: [nilai]}, 'errors': {tipe: pesan}}.
# MX berbentuk "preference exchange". Kegagalan dicatat di 'errors'.
```

## scanner.reconnaissance.whois_enhanced

```python
class WhoisError(Exception)

whois_lookup(domain: str, timeout: float = 10.0) -> Dict
# {'domain', 'server', 'raw_response', 'error'}. Alur: whois.iana.org →
# server registry TLD. Respons MENTAH (format bervariasi antar registrar).
```

## config.settings

```python
class Config:
    __init__(config_file="config.json")   # buat file default bila belum ada
    get(key_path, default=None)           # dot notation, mis. 'scan_settings.timeout'
    set(key_path, value)                  # langsung disimpan ke file
    save_config(); load_config()
```

## database.models

```python
class DatabaseManager:
    __init__(db_path="scans.db")          # membuat tabel bila belum ada
    save_scan_session(target, scan_type, results, risk_score=0,
                      duration=0.0, status="completed") -> int
    get_scan_history(limit=50) -> List[Tuple]
    # (id, target, scan_type, timestamp, results_json, risk_score, status, duration)
    get_scan_by_id(scan_id) -> Optional[Tuple]
    delete_scan(scan_id) -> bool
    get_statistics() -> Dict
```

## database.queries

```python
save_scan_session_result(db, result, scan_type=None, status="completed") -> int
load_scan_session_result(db, session_id) -> Optional[Dict]   # None bila tak ada
```

## gui.worker

```python
class TaskRunner:
    __init__(root: tk.Misc)
    start(target, on_done, on_error, on_progress=None, cancel_token=None) -> bool
    # target(progress_cb, cancel_token); False bila masih ada tugas berjalan.
    cancel() -> None        # teruskan ke token (kooperatif)
    shutdown() -> None      # hentikan polling + batalkan timer after tertunda
    wait(timeout=None)      # join thread worker (bila ada)
    busy: bool
```

## gui.exports

```python
CSV_PORT_COLUMNS = ["port", "status", "duration_ms", "error"]

write_json_result(path, result) -> None        # JSON UTF-8, tipe dipertahankan
port_rows_for_csv(result) -> List[Dict]        # ValueError bila bukan hasil port
write_csv_ports(path, result) -> None          # CSV header jelas, UTF-8
```

## gui.results_viewer

```python
sort_key(value) -> Tuple          # angka numerik; teks case-insensitive; None=""
class SortableTable(ttk.Frame):
    set_rows(rows, ids=None, tags=None)
    # ganti isi; urutan sortir aktif dipertahankan. ids: identitas baris
    # (diambil via selected_id()); tags: tag pewarnaan baris (mis. status).
    clear()
    get_values() -> List[Tuple]
    selected_values() -> Optional[Tuple]
    selected_id() -> Any          # identitas baris terpilih (dari ids)
```

## gui.theme

```python
BG, PANEL, INPUT, BORDER, TEXT, MUTED, ACCENT, SELECT_BG  # palet gelap
STATUS_OPEN, STATUS_CLOSED, STATUS_UNKNOWN               # warna status
UI_FONT = "Segoe UI"; MONO_FONT = "Consolas"

apply_theme(root) -> None        # tema clam + style ttk → palet gelap
apply_status_tags(tree) -> None  # tag baris Terbuka/Tertutup/Tidak pasti
```

## gui.scan_tabs (fungsi bantu murni)

```python
label_port_status(status) -> str    # open→"Terbuka", filtered→"Tidak pasti", ...
label_scan_status(status) -> str    # completed→"Selesai", cancelled, failed
label_scan_type(scan_type) -> str
format_timestamp(value) -> str      # ISO → "YYYY-MM-DD HH:MM:SS"; "-" bila kosong
format_summary(result) -> str       # ringkasan kolom Riwayat; "-" untuk hasil gagal
format_duration(value) -> str       # "0.0"; "-" bila tidak valid
export_result(parent, result, kind, on_status=None) -> bool
# kind: 'json' | 'csv' (csv hanya hasil port); True bila tersimpan.
```
