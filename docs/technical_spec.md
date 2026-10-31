# Spesifikasi Teknis — OSINT Port Scanner

## Arsitektur modul

```
main.py                     titik masuk; import gui.main_window.MainWindow
config/settings.py          Config: load/simpan config.json, get/set dot-notation
database/models.py          DatabaseManager: SQLite, koneksi per operasi + close
database/queries.py         save/load hasil scan (lapisan tipis di atas models)
scanner/utils/ip_utils.py   validasi target & resolusi IP/hostname
scanner/utils/rate_limiter.py       RateLimiter global antar-thread
scanner/utils/threading_manager.py  CancellationToken + BoundedPool
scanner/network/port_scanner.py     scan TCP connect
scanner/reconnaissance/dns_enum.py  lookup record DNS (dnspython)
scanner/reconnaissance/whois_enhanced.py  WHOIS TCP 43 (stdlib)
gui/worker.py               TaskRunner (queue + root.after)
gui/scan_tabs.py            5 tab + dialog detail riwayat
gui/exports.py              penulis JSON/CSV murni (tanpa Tk)
gui/results_viewer.py       SortableTable (Treeview + sortir kolom)
gui/settings_dialog.py      dialog pengaturan terhubung Config
gui/theme.py                tema gelap (clam) + tag pewarnaan status
gui/main_window.py          jendela utama, menu, riwayat, penutupan aman
```

Aturan lapisan: GUI **tidak menduplikasi** logika scanner — tab hanya
memanggil API publik scanner; skema database hanya milik `models.py`.

## Model threading GUI

Satu worker per aplikasi, satu tugas pada satu waktu (`TaskRunner.busy`):

```
worker thread:  target(progress_cb, token) → queue.Queue
                ("progress", args) | ("done", hasil) | ("error", detail)
main thread:    root.after(50ms) → _poll() → _drain() → callback widget
```

- Widget Tk **hanya** disentuh dari main thread; callback progress scanner
  dibungkus agar masuk antrean, bukan dipanggil langsung di worker.
- `_TaskThread` melepas `_target/_args` saat selesai (mencegah siklus
  referensi Thread↔closure↔tab — finalisasi objek Tk di thread non-main
  merusak interpreter Tcl).
- `wait()` (join) dipanggil sebelum objek Tk dilepas agar finalisasi tidak
  terjadi di thread worker.
- `shutdown()` membatalkan timer `after` yang tertunda dan menghentikan
  polling — dipanggil saat jendela ditutup; `_poll` juga mendeteksi window
  yang sudah dihancurkan dan tidak me-re-arm timer.
- Penutupan saat scan berjalan: konfirmasi → `cancel()` → pompa event loop
  (maks. 2 dtk) agar hasil "Dibatalkan" sempat tersimpan ke riwayat →
  `wait(2.0)` → `shutdown()` → `destroy()`.
- `CancellationToken` kooperatif; socket yang sedang connect menunggu
  timeoutnya (bukan di-interrupt paksa). Thread worker adalah daemon.

## Tema antarmuka (gui.theme)

- Tema `clam` dipakai agar semua warna bisa diatur; palet gelap (latar
  `#101318`, teks `#E4E8ED`, aksen `#7396B5`) identik di source dan exe.
- `apply_theme(root)` memetakan style ttk (frame, label, Treeview, tombol,
  tab) ke palet; `apply_status_tags(tree)` menandai baris hasil dengan
  warna status: hijau Terbuka, merah Tertutup, amber Tidak pasti.

## Semantik status

Status port (`scan_tcp_ports`):

| Nilai | Kondisi |
|---|---|
| `open` | `socket.create_connection` berhasil |
| `closed` | ConnectionRefused/ConnectionReset |
| `filtered_or_unknown` | timeout atau OSError lain — tidak disimpulkan |

Port yang dilewati karena pembatalan **tidak** masuk `ports`; dihitung di
`summary.skipped`. Hasil memuat `cancelled: true` bila dibatalkan.

Status sesi riwayat: `completed` / `failed` / `cancelled` (ditampilkan
Selesai/Gagal/Dibatalkan). Sesi `failed` menyimpan `error` (baris pertama)
dan `error_detail` (traceback lengkap).

## Skema database (SQLite, `scans.db`)

Tabel dibuat oleh `DatabaseManager.init_database()` (`CREATE TABLE IF NOT
EXISTS`) — tidak ada migrasi diam-diam.

- `scan_sessions(id, target, scan_type, timestamp, results JSON, risk_score,
  status, duration)` — dipakai aplikasi.
- `discovered_hosts`, `vulnerabilities`, `api_usage` — ada, tetapi **tidak
  diisi** oleh fitur saat ini (port terbuka TIDAK disimpan sebagai
  kerentanan; hanya `tcp_ports` hasil scan yang disimpan di
  `discovered_hosts.open_ports` untuk sesi `completed`).

Koneksi sqlite dibuat per operasi dan ditutup via `try/finally`.

## Konfigurasi (config.json)

Kunci yang dipakai aplikasi:

- `scan_settings.timeout` (default 5), `max_threads` (50),
  `rate_limit` (10), `common_ports` (20 port), `extended_ports` (1–1024).
- `security.rate_limiting` (default true) — mengaktifkan RateLimiter.
- `ui_settings.auto_save` (default true) — simpan otomatis ke riwayat.

Kunci lain di file default (`api_keys`, `stealth_mode`, `enable_udp_scan`,
`banner_grabbing`, dsb.) **tidak dipakai** implementasi saat ini dan tidak
ditampilkan. `Config` menggabungkan file dengan default (deepcopy — mutasi
hasil load tidak mencemari default).

## Format ekspor

- JSON: `json.dump(..., ensure_ascii=False, indent=2)`, UTF-8; tipe data
  dipertahankan; tidak pernah memuat kredensial.
- CSV: hanya hasil `tcp_connect`; kolom `port,status,duration_ms,error`;
  `newline=""`, UTF-8. Hasil lain ditolak dengan pesan jujur.

## Distribusi Windows (PyInstaller)

- Spec: `packaging/osint_port_scanner.spec` — mode **onedir**, tanpa
  konsol (`console=False`), nama `OSINTPortScanner`, metadata versi dari
  `packaging/version_info.txt` (0.3.0), exclude `unittest`/`tkinter.test`/
  `pydoc`. tkinter/tcl-tk dan dnspython (pure-Python) terdeteksi otomatis;
  tidak ada resource eksternal yang dibundel.
- Build: `packaging/build_windows.bat` — venv khusus `packaging\venv`
  (PyInstaller + dnspython, tanpa menyentuh instalasi global); output
  `dist\OSINTPortScanner\`.
- Lokasi data saat frozen: `gui.main_window._default_data_dir()` →
  jika `sys.frozen`: `%LOCALAPPDATA%\OSINT Port Scanner` (fallback `~`
  bila LOCALAPPDATA tidak tersedia); jika source: `PROJECT_ROOT`
  (tidak berubah dari perilaku sebelumnya). Executable tidak pernah
  menulis ke direktori instalasi (onedir di Program Files tidak dapat
  ditulis) maupun folder ekstraksi sementara (onefile %TEMP% — data
  hilang saat keluar).
- Perbedaan source vs exe **hanya** pada lokasi data; fitur, skema
  database, dan versi aplikasi (0.3.0) identik.

## Batasan yang diketahui (disengaja)

1. Tidak ada identifikasi service/banner/versi dan tidak ada deteksi
   kerentanan.
2. Di Windows, port loopback tanpa listener sering men-drop SYN tanpa RST
   → `closed` nyata sulit teramati di localhost (hasil "Tidak pasti").
3. Pembatalan tidak memutus socket yang sedang connect (menunggu timeout).
4. Preset Extended (1–1024) dengan batas laju rendah bisa sangat lama.
5. `whois_lookup` memakai timeout tetap 10 dtk per koneksi (tidak
   dikonfigurasi lewat dialog).
