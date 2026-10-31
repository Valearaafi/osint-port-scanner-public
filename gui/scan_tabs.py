"""Tab pemindaian (IP/DNS/WHOIS/Port) dan tab Riwayat untuk jendela utama.

Semua pemindaian berjalan lewat TaskRunner; widget hanya disentuh dari
main thread. Tab tidak menduplikasi logika scanner — hanya memanggil API
scanner yang sudah ada.
"""

import json
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from database.queries import load_scan_session_result
from gui.exports import port_rows_for_csv, write_csv_ports, write_json_result
from gui.results_viewer import SortableTable
from gui.theme import BG, BORDER, INPUT, STATUS_UNKNOWN, TEXT
from scanner.network.port_scanner import (
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_OPEN,
    resolve_port_list,
    scan_tcp_ports,
)
from scanner.reconnaissance.dns_enum import lookup_records
from scanner.reconnaissance.whois_enhanced import whois_lookup
from scanner.utils.ip_utils import resolve_target
from scanner.utils.rate_limiter import create_rate_limiter
from scanner.utils.threading_manager import CancellationToken

PORT_STATUS_LABELS = {
    STATUS_OPEN: "Terbuka",
    STATUS_CLOSED: "Tertutup",
    STATUS_FILTERED: "Tidak pasti",
}

PORT_STATUS_TAGS = {
    STATUS_OPEN: "open",
    STATUS_CLOSED: "closed",
    STATUS_FILTERED: "filtered",
}

SESSION_STATUS_TAGS = {
    "completed": None,
    "cancelled": "warning",
    "failed": "error",
}

SCAN_STATUS_LABELS = {
    "completed": "Selesai",
    "cancelled": "Dibatalkan",
    "failed": "Gagal",
}

SCAN_TYPE_LABELS = {
    "ip_lookup": "IP Lookup",
    "dns_lookup": "DNS Lookup",
    "whois_lookup": "WHOIS Lookup",
    "tcp_connect": "Port Scanner",
}

TARGET_KIND_LABELS = {
    "ipv4": "Alamat IPv4",
    "ipv6": "Alamat IPv6",
    "hostname": "Hostname",
}

PRESET_KEYS = {"Umum": "common", "Extended": "extended", "Kustom": "custom"}


def label_port_status(status):
    """Label Indonesia untuk status port."""
    return PORT_STATUS_LABELS.get(status, str(status))


def label_scan_status(status):
    """Label Indonesia untuk status sesi riwayat."""
    return SCAN_STATUS_LABELS.get(status, str(status))


def label_scan_type(scan_type):
    """Label tampilan untuk jenis pemindaian."""
    return SCAN_TYPE_LABELS.get(scan_type, str(scan_type or "-"))


def format_timestamp(value):
    """Normalisasi timestamp sqlite (ISO) menjadi 'YYYY-MM-DD HH:MM:SS'."""
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


def format_summary(result):
    """Ringkasan singkat hasil pemindaian untuk kolom Riwayat.

    Hasil gagal (ada 'error' tanpa data) ditampilkan '-' — tidak
    memalsukan ringkasan pemindaian yang tidak pernah menghasilkan data.
    """
    if not isinstance(result, dict):
        return "-"
    scan_type = result.get("scan_type")
    error = result.get("error")
    if scan_type == "tcp_connect":
        summary = result.get("summary") or {}
        ports = result.get("ports") or []
        if error and not ports:
            return "-"
        total = len(ports) + int(summary.get("skipped") or 0)
        return f"{total} port · {summary.get('open', 0)} terbuka"
    if scan_type == "ip_lookup":
        ipv4 = result.get("ipv4") or []
        ipv6 = result.get("ipv6") or []
        if error and not ipv4 and not ipv6:
            return "-"
        return f"{len(ipv4)} alamat IPv4, {len(ipv6)} alamat IPv6"
    if scan_type == "dns_lookup":
        records = result.get("records") or {}
        count = sum(len(values) for values in records.values())
        if error and not count:
            return "-"
        return f"{count} record DNS"
    if scan_type == "whois_lookup":
        raw = result.get("raw_response") or ""
        if error and not raw:
            return "-"
        return f"{len(raw)} karakter WHOIS"
    return "-"


def format_duration(value):
    """Durasi detik dalam format '0.0'; '-' bila tidak valid/rusak."""
    try:
        return f"{float(value or 0):.1f}"
    except (TypeError, ValueError):
        return "-"


def export_result(parent, result, kind, on_status=None):
    """Ekspor hasil ke JSON/CSV lewat dialog simpan.

    CSV hanya untuk hasil pemindaian port. Kembalikan True bila tersimpan.
    """
    target = str(result.get("target") or "hasil")
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
    safe_name = safe_name or "hasil"
    if kind == "json":
        writer = write_json_result
        path = filedialog.asksaveasfilename(
            parent=parent, defaultextension=".json", initialfile=f"scan_{safe_name}.json",
            filetypes=[("JSON", "*.json"), ("Semua berkas", "*.*")])
    else:
        try:
            port_rows_for_csv(result)
        except ValueError as exc:
            messagebox.showinfo("Ekspor CSV", str(exc), parent=parent)
            return False
        writer = write_csv_ports
        path = filedialog.asksaveasfilename(
            parent=parent, defaultextension=".csv", initialfile=f"scan_{safe_name}.csv",
            filetypes=[("CSV", "*.csv"), ("Semua berkas", "*.*")])
    if not path:
        return False
    try:
        writer(path, result)
    except OSError as exc:
        messagebox.showerror("Gagal menyimpan", f"Berkas tidak bisa ditulis:\n{exc}",
                             parent=parent)
        return False
    if on_status is not None:
        on_status(f"Tersimpan: {path}")
    return True


def build_tab_header(parent, title, description):
    """Header standar tiap tab: judul fitur + deskripsi satu baris."""
    header = ttk.Frame(parent)
    ttk.Label(header, text=title, style="TabHeader.TLabel").grid(
        row=0, column=0, sticky="w")
    ttk.Label(header, text=description, style="TabDesc.TLabel").grid(
        row=1, column=0, sticky="w", pady=(2, 0))
    header.columnconfigure(0, weight=1)
    return header


class ScanTab(ttk.Frame):
    """Kerangka tab pemindaian: berbagi target, runner, dan alur mulai/selesai."""

    title = ""
    description = ""
    scan_type = None

    def __init__(self, master, config, runner, target_var, on_status, on_result):
        super().__init__(master, padding=12)
        self.config = config
        self.runner = runner
        self.target_var = target_var
        self.on_status = on_status
        self.on_result = on_result
        self._result = None
        self._inputs = []
        self._cancel_button = None

        header = build_tab_header(self, self.title, self.description)
        header.grid(row=0, column=0, sticky="ew")
        self.body = ttk.Frame(self)
        self.body.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.columnconfigure(0, weight=1)
        self.body.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

    def _register_inputs(self, *widgets):
        self._inputs = [w for w in widgets if w is not None]

    def set_inputs_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for widget in self._inputs:
            try:
                widget.configure(state=state)
            except tk.TclError:
                pass

    def _set_cancel_enabled(self, enabled):
        if self._cancel_button is None:
            return
        try:
            self._cancel_button.configure(state="normal" if enabled else "disabled")
        except tk.TclError:
            pass

    def _build_action_row(self):
        """Baris tombol Mulai untuk tab tanpa konfigurasi tambahan."""
        action_row = ttk.Frame(self.body)
        start_btn = ttk.Button(action_row, text="Mulai",
                               style="Accent.TButton", command=self.start)
        start_btn.grid(row=0, column=0)
        return action_row, start_btn

    def start(self):
        raise NotImplementedError

    def cancel(self):
        """Minta pembatalan tugas yang sedang berjalan (kooperatif)."""
        self.runner.cancel()
        self.on_status(f"{self.title}: membatalkan…")

    def get_result(self):
        return self._result

    def _run_task(self, target, cancel_token=None, on_progress=None):
        if not self.runner.start(target, self._on_done, self._on_error,
                                 on_progress=on_progress,
                                 cancel_token=cancel_token):
            messagebox.showwarning(
                "Sedang berjalan",
                "Pemindaian masih berjalan. Tunggu sampai selesai atau batalkan dulu.",
                parent=self.winfo_toplevel())
            return False
        self._result = None
        self.set_inputs_enabled(False)
        self._set_cancel_enabled(cancel_token is not None)
        self.on_status(f"{self.title}: memindai…")
        return True

    def _on_done(self, result):
        self._result = result
        self.set_inputs_enabled(True)
        self._set_cancel_enabled(False)
        if result.get("cancelled"):
            self.on_status(f"{self.title}: dibatalkan.")
            self.on_result(result, "cancelled")
        else:
            self.on_status(f"{self.title}: selesai.")
            self.on_result(result, "completed")

    def _on_error(self, message):
        self.set_inputs_enabled(True)
        self._set_cancel_enabled(False)
        self.on_status(f"{self.title}: gagal.")
        first_line = (message.splitlines() or ["Terjadi kesalahan."])[0]
        if ": " in first_line:
            _prefix, _, first_line = first_line.partition(": ")
        messagebox.showerror("Gagal", first_line, parent=self.winfo_toplevel())
        self.on_result(
            {
                "scan_type": self.scan_type,
                "target": self.target_var.get().strip(),
                "error": first_line,
                "error_detail": message,
            },
            "failed")


class IpLookupTab(ScanTab):
    title = "IP Lookup"
    description = "Resolusi alamat IPv4 dan IPv6 untuk hostname atau alamat IP."
    scan_type = "ip_lookup"

    def __init__(self, master, config, runner, target_var, on_status, on_result):
        super().__init__(master, config, runner, target_var, on_status, on_result)
        self.body.rowconfigure(1, weight=1)
        action_row, start_btn = self._build_action_row()
        action_row.grid(row=0, column=0, sticky="w")
        self.table = SortableTable(self.body, ["jenis", "nilai"],
                                   headings=["Jenis", "Nilai"],
                                   column_widths={"jenis": 170, "nilai": 460})
        self.table.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._register_inputs(start_btn)

    def start(self):
        if not self.target_var.get().strip():
            messagebox.showwarning("Target kosong", "Isi target terlebih dahulu.",
                                   parent=self.winfo_toplevel())
            return
        self.table.clear()
        self._run_task(self._run)

    def _run(self, progress_cb, cancel_token):
        resolved = resolve_target(self.target_var.get().strip())
        resolved["scan_type"] = "ip_lookup"
        return resolved

    def _on_done(self, result):
        kind = result.get("kind") or ""
        rows = [("Jenis target", TARGET_KIND_LABELS.get(kind, kind or "-"))]
        for address in result.get("ipv4") or []:
            rows.append(("Alamat IPv4", address))
        for address in result.get("ipv6") or []:
            rows.append(("Alamat IPv6", address))
        self.table.set_rows(rows)
        super()._on_done(result)


class DnsLookupTab(ScanTab):
    title = "DNS Lookup"
    description = "Pemeriksaan record DNS (A, AAAA, NS, MX) untuk sebuah domain."
    scan_type = "dns_lookup"

    def __init__(self, master, config, runner, target_var, on_status, on_result):
        super().__init__(master, config, runner, target_var, on_status, on_result)
        self.body.rowconfigure(1, weight=1)
        action_row, start_btn = self._build_action_row()
        action_row.grid(row=0, column=0, sticky="w")
        self.table = SortableTable(self.body, ["tipe", "nilai"],
                                   headings=["Tipe Record", "Nilai"],
                                   column_widths={"tipe": 110, "nilai": 520})
        self.table.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self.errors_box = tk.Text(self.body, height=4, wrap="word",
                                  state="disabled", relief="flat",
                                  background=INPUT, foreground=STATUS_UNKNOWN,
                                  font="TkFixedFont", highlightthickness=1,
                                  highlightbackground=BORDER,
                                  highlightcolor=BORDER, padx=8, pady=6)
        self.errors_box.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.errors_box.grid_remove()
        self._register_inputs(start_btn)

    def start(self):
        if not self.target_var.get().strip():
            messagebox.showwarning("Domain kosong", "Isi domain terlebih dahulu.",
                                   parent=self.winfo_toplevel())
            return
        self.table.clear()
        self._set_errors([])
        self._run_task(self._run)

    def _run(self, progress_cb, cancel_token):
        domain = self.target_var.get().strip()
        timeout = float(self.config.get("scan_settings.timeout", 5))
        result = lookup_records(domain, timeout=timeout)
        result["scan_type"] = "dns_lookup"
        result["target"] = domain
        return result

    def _on_done(self, result):
        records = result.get("records") or {}
        rows = [(record_type, value)
                for record_type in ("A", "AAAA", "NS", "MX")
                for value in records.get(record_type, [])]
        errors = result.get("errors") or {}
        self._set_errors([f"{record_type}: {message}"
                          for record_type, message in sorted(errors.items())])
        self.table.set_rows(rows)
        super()._on_done(result)

    def _set_errors(self, lines):
        self.errors_box.configure(state="normal")
        self.errors_box.delete("1.0", "end")
        if lines:
            self.errors_box.insert("1.0", "\n".join(lines))
            self.errors_box.grid()
        else:
            self.errors_box.grid_remove()
        self.errors_box.configure(state="disabled")


class WhoisLookupTab(ScanTab):
    title = "WHOIS Lookup"
    description = "Informasi registrasi domain dari server WHOIS."
    scan_type = "whois_lookup"

    def __init__(self, master, config, runner, target_var, on_status, on_result):
        super().__init__(master, config, runner, target_var, on_status, on_result)
        self.body.rowconfigure(2, weight=1)
        action_row, start_btn = self._build_action_row()
        action_row.grid(row=0, column=0, sticky="w")
        self.server_var = tk.StringVar(value="")
        self.server_label = ttk.Label(self.body, textvariable=self.server_var,
                                      style="Muted.TLabel")
        self.server_label.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.text = tk.Text(self.body, wrap="word", state="disabled",
                            font="TkFixedFont", relief="flat",
                            background=INPUT, foreground=TEXT,
                            highlightthickness=1, highlightbackground=BORDER,
                            highlightcolor=BORDER, padx=8, pady=6)
        vsb = ttk.Scrollbar(self.body, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        self.text.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        vsb.grid(row=2, column=1, sticky="ns", pady=(8, 0))
        self._register_inputs(start_btn)

    def start(self):
        if not self.target_var.get().strip():
            messagebox.showwarning("Domain kosong", "Isi domain terlebih dahulu.",
                                   parent=self.winfo_toplevel())
            return
        self._set_text("")
        self.server_var.set("")
        self._run_task(self._run)

    def _run(self, progress_cb, cancel_token):
        target = self.target_var.get().strip()
        result = whois_lookup(target, timeout=10.0)
        result["scan_type"] = "whois_lookup"
        result["target"] = result.get("domain") or target
        return result

    def _on_done(self, result):
        self.server_var.set(f"Server WHOIS: {result.get('server') or '-'}")
        raw = result.get("raw_response") or ""
        if raw:
            self._set_text(raw)
        elif result.get("error"):
            self._set_text(f"Tidak ada respons WHOIS.\n\n{result['error']}")
        else:
            self._set_text("Tidak ada respons WHOIS.")
        super()._on_done(result)

    def _set_text(self, content):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.configure(state="disabled")


class PortScannerTab(ScanTab):
    title = "Port Scanner"
    description = "Pemeriksaan status port TCP dengan koneksi langsung."
    scan_type = "tcp_connect"

    TABLE_COLUMNS = ["port", "status", "duration_ms", "error"]
    TABLE_HEADINGS = ["Port", "Status", "Waktu (ms)", "Keterangan"]

    def __init__(self, master, config, runner, target_var, on_status, on_result):
        super().__init__(master, config, runner, target_var, on_status, on_result)
        self.body.rowconfigure(4, weight=1)

        row = ttk.Frame(self.body)
        row.grid(row=0, column=0, sticky="ew")
        ttk.Label(row, text="Preset:").grid(row=0, column=0, padx=(0, 4))
        self.preset_var = tk.StringVar(value="Umum")
        preset = ttk.Combobox(row, textvariable=self.preset_var, state="readonly",
                              values=list(PRESET_KEYS), width=9)
        preset.grid(row=0, column=1, padx=(0, 14))
        preset.bind("<<ComboboxSelected>>", lambda _e: self._sync_custom_entry())
        ttk.Label(row, text="Timeout (dt):").grid(row=0, column=2, padx=(0, 4))
        self.timeout_var = tk.StringVar(
            value=str(config.get("scan_settings.timeout", 5)))
        timeout_box = ttk.Spinbox(row, from_=0.5, to=60.0, increment=0.5,
                                  textvariable=self.timeout_var, width=5)
        timeout_box.grid(row=0, column=3, padx=(0, 14))
        ttk.Label(row, text="Worker:").grid(row=0, column=4, padx=(0, 4))
        self.workers_var = tk.StringVar(
            value=str(config.get("scan_settings.max_threads", 50)))
        workers_box = ttk.Spinbox(row, from_=1, to=500, increment=1,
                                  textvariable=self.workers_var, width=5)
        workers_box.grid(row=0, column=5)

        custom_row = ttk.Frame(self.body)
        custom_row.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        custom_row.columnconfigure(1, weight=1)
        ttk.Label(custom_row, text="Port kustom:").grid(row=0, column=0,
                                                        sticky="w", padx=(0, 6))
        self.custom_var = tk.StringVar()
        self.custom_entry = ttk.Entry(custom_row, textvariable=self.custom_var,
                                      width=36)
        self.custom_entry.grid(row=0, column=1, sticky="ew")
        self.custom_hint = ttk.Label(custom_row, text="Contoh: 80, 443, 8000-8010",
                                     style="Muted.TLabel")
        self.custom_hint.grid(row=0, column=2, padx=(10, 0), sticky="w")

        button_row = ttk.Frame(self.body)
        button_row.grid(row=2, column=0, sticky="w", pady=(10, 0))
        start_btn = ttk.Button(button_row, text="Mulai",
                               style="Accent.TButton", command=self.start)
        start_btn.grid(row=0, column=0, padx=(0, 6))
        self._cancel_button = ttk.Button(button_row, text="Batal",
                                         command=self.cancel, state="disabled")
        self._cancel_button.grid(row=0, column=1)

        progress_row = ttk.Frame(self.body)
        progress_row.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        progress_row.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_row, mode="determinate",
                                        maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress_count = ttk.Label(progress_row, text="",
                                        style="Muted.TLabel", width=8,
                                        anchor="e")
        self.progress_count.grid(row=0, column=1, padx=(8, 0))

        self.table = SortableTable(
            self.body, self.TABLE_COLUMNS, headings=self.TABLE_HEADINGS,
            column_widths={"port": 80, "status": 110, "duration_ms": 110,
                           "error": 330})
        self.table.grid(row=4, column=0, sticky="nsew", pady=(10, 0))

        self.summary_var = tk.StringVar(value="")
        ttk.Label(self.body, textvariable=self.summary_var,
                  style="Muted.TLabel").grid(
            row=5, column=0, sticky="w", pady=(6, 0))

        self._partial_rows = []
        self._last_table_update = 0.0
        self._register_inputs(preset, timeout_box, workers_box, start_btn)
        self._sync_custom_entry()

    def _sync_custom_entry(self):
        enabled = self.preset_var.get() == "Kustom"
        self.custom_entry.configure(state="normal" if enabled else "disabled")
        self.custom_hint.configure(state="normal" if enabled else "disabled")

    def start(self):
        if not self.target_var.get().strip():
            messagebox.showwarning("Target kosong", "Isi target terlebih dahulu.",
                                   parent=self.winfo_toplevel())
            return
        preset_key = PRESET_KEYS.get(self.preset_var.get(), "common")
        custom_text = self.custom_var.get().strip() if preset_key == "custom" else ""
        try:
            ports = resolve_port_list(self.config, preset_key, custom_text)
        except ValueError as exc:
            messagebox.showerror("Daftar port tidak valid", str(exc),
                                 parent=self.winfo_toplevel())
            return
        if not ports:
            messagebox.showerror("Daftar port kosong",
                                 "Tidak ada port yang bisa dipindai.",
                                 parent=self.winfo_toplevel())
            return
        try:
            timeout = float(self.timeout_var.get())
            workers = int(self.workers_var.get())
        except ValueError:
            messagebox.showerror("Nilai tidak valid",
                                 "Timeout dan jumlah worker harus berupa angka.",
                                 parent=self.winfo_toplevel())
            return
        if not (0.5 <= timeout <= 60.0):
            messagebox.showerror("Nilai tidak valid",
                                 "Timeout harus antara 0,5 dan 60 detik.",
                                 parent=self.winfo_toplevel())
            return
        if not (1 <= workers <= 500):
            messagebox.showerror("Nilai tidak valid",
                                 "Jumlah worker harus antara 1 dan 500.",
                                 parent=self.winfo_toplevel())
            return
        cancel_token = CancellationToken()
        rate_limiter = create_rate_limiter(self.config)
        target_text = self.target_var.get().strip()

        def _run(progress_cb, token):
            return scan_tcp_ports(
                target_text,
                ports,
                timeout=timeout,
                max_threads=workers,
                rate_limiter=rate_limiter,
                cancel_token=token,
                on_progress=progress_cb,
            )

        if self._run_task(_run, cancel_token=cancel_token,
                          on_progress=self._on_progress):
            self._reset_ui(len(ports))

    def _reset_ui(self, total):
        self.table.clear()
        self._partial_rows = []
        self._last_table_update = time.monotonic()
        self.progress.configure(maximum=total, value=0)
        self.progress_count.configure(text=f"0/{total}")
        self.summary_var.set("")
        self._sync_custom_entry()

    def _on_progress(self, checked, total, last):
        if last is not None:
            self._partial_rows.append(last)
        self.progress.configure(maximum=total, value=checked)
        self.progress_count.configure(text=f"{checked}/{total}")
        now = time.monotonic()
        if checked >= total or now - self._last_table_update >= 0.25:
            self._last_table_update = now
            self._render_rows()

    def _render_rows(self):
        rows = sorted(
            (row["port"], label_port_status(row.get("status")),
             self._format_ms(row.get("duration_ms")), row.get("error") or "")
            for row in self._partial_rows)
        tags = [PORT_STATUS_TAGS.get(row.get("status"))
                for row in self._partial_rows]
        self.table.set_rows(rows, tags=tags)

    @staticmethod
    def _format_ms(value):
        if value is None:
            return ""
        try:
            return f"{float(value):.1f}"
        except (TypeError, ValueError):
            return str(value)

    def _on_done(self, result):
        self._partial_rows = list(result.get("ports") or [])
        self._render_rows()
        summary = result.get("summary") or {}
        self.summary_var.set(
            f"Terbuka: {summary.get('open', 0)} · "
            f"Tertutup: {summary.get('closed', 0)} · "
            f"Tidak pasti: {summary.get('filtered_or_unknown', 0)} · "
            f"Dilewati: {summary.get('skipped', 0)}")
        self._sync_custom_entry()
        super()._on_done(result)

    def _on_error(self, message):
        super()._on_error(message)
        self._sync_custom_entry()


class HistoryTab(ttk.Frame):
    """Tab Riwayat: daftar sesi pemindaian tersimpan + detail + ekspor."""

    COLUMNS = ["waktu", "target", "jenis", "status", "durasi", "ringkasan"]

    def __init__(self, master, db, on_status):
        super().__init__(master, padding=12)
        self.db = db
        self.on_status = on_status
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = build_tab_header(
            self, "Riwayat",
            "Riwayat pemindaian tersimpan (maks. 100 sesi terbaru).")
        header.grid(row=0, column=0, sticky="ew")

        body = ttk.Frame(self)
        body.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)

        toolbar = ttk.Frame(body)
        toolbar.grid(row=0, column=0, sticky="w")
        ttk.Button(toolbar, text="Segarkan", command=self.refresh).grid(
            row=0, column=0, padx=(0, 6))
        ttk.Button(toolbar, text="Lihat Detail", command=self._show_detail).grid(
            row=0, column=1, padx=(0, 6))
        ttk.Button(toolbar, text="Hapus", command=self._delete_selected).grid(
            row=0, column=2, padx=(0, 6))
        ttk.Button(toolbar, text="Ekspor JSON…", command=self._export_json).grid(
            row=0, column=3, padx=(0, 6))
        ttk.Button(toolbar, text="Ekspor CSV…", command=self._export_csv).grid(
            row=0, column=4)

        self.empty_label = ttk.Label(body, text="Belum ada riwayat pemindaian.",
                                     style="Muted.TLabel")
        self.empty_label.grid(row=1, column=0, sticky="w", pady=(12, 0))

        self.table = SortableTable(
            body, self.COLUMNS,
            headings=["Waktu", "Target", "Jenis", "Status", "Durasi (s)",
                      "Ringkasan"],
            column_widths={"waktu": 150, "target": 180, "jenis": 110,
                           "status": 100, "durasi": 80, "ringkasan": 240})
        self.table.grid(row=2, column=0, sticky="nsew", pady=(8, 0))
        self.refresh()

    def refresh(self):
        try:
            rows = self.db.get_scan_history(limit=100)
        except Exception as exc:
            messagebox.showerror("Gagal memuat riwayat", str(exc),
                                 parent=self.winfo_toplevel())
            rows = []
        if rows:
            self.empty_label.grid_remove()
        else:
            self.empty_label.grid()
        display, ids, tags = [], [], []
        for row in rows:
            session_id, target, scan_type, timestamp, results_json, _risk, status, duration = row
            results = self._parse_results(results_json)
            display.append((
                format_timestamp(timestamp),
                target,
                label_scan_type(scan_type),
                label_scan_status(status),
                format_duration(duration),
                format_summary(results),
            ))
            ids.append(session_id)
            tags.append(SESSION_STATUS_TAGS.get(status))
        self.table.set_rows(display, ids=ids, tags=tags)

    @staticmethod
    def _parse_results(text):
        try:
            return json.loads(text)
        except (TypeError, ValueError):
            return None

    def _selected_session(self):
        session_id = self.table.selected_id()
        if session_id is None:
            messagebox.showinfo("Pilih baris",
                                "Pilih baris riwayat terlebih dahulu.",
                                parent=self.winfo_toplevel())
            return None
        result = load_scan_session_result(self.db, session_id)
        if result is None:
            messagebox.showwarning("Data tidak terbaca",
                                   "Hasil sesi ini tidak bisa dibaca.",
                                   parent=self.winfo_toplevel())
            return None
        return session_id, result

    def _show_detail(self):
        selected = self._selected_session()
        if selected is None:
            return
        HistoryDetailDialog(self.winfo_toplevel(), selected[1])

    def _delete_selected(self):
        session_id = self.table.selected_id()
        if session_id is None:
            messagebox.showinfo("Pilih baris",
                                "Pilih baris riwayat terlebih dahulu.",
                                parent=self.winfo_toplevel())
            return
        if not messagebox.askyesno("Hapus riwayat",
                                   "Hapus sesi ini dari riwayat?",
                                   parent=self.winfo_toplevel()):
            return
        if not self.db.delete_scan(session_id):
            messagebox.showerror("Gagal menghapus",
                                 "Sesi tidak bisa dihapus dari riwayat.",
                                 parent=self.winfo_toplevel())
        self.refresh()

    def _export_json(self):
        selected = self._selected_session()
        if selected is None:
            return
        export_result(self.winfo_toplevel(), selected[1], "json", self.on_status)

    def _export_csv(self):
        selected = self._selected_session()
        if selected is None:
            return
        export_result(self.winfo_toplevel(), selected[1], "csv", self.on_status)


class HistoryDetailDialog(tk.Toplevel):
    """Dialog detail satu sesi riwayat dengan tombol ekspor."""

    def __init__(self, parent, result):
        super().__init__(parent)
        self.title("Detail Riwayat")
        self.geometry("680x520")
        self.transient(parent)
        self.configure(background=BG)
        self.result = result

        body = ttk.Frame(self, padding=10)
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        header = (f"{result.get('target') or '-'} — "
                  f"{label_scan_type(result.get('scan_type'))}")
        ttk.Label(body, text=header, style="TabHeader.TLabel").grid(
            row=0, column=0, sticky="w")
        self.text = tk.Text(body, wrap="word", font="TkFixedFont",
                            state="disabled", background=INPUT,
                            foreground=TEXT, relief="flat",
                            highlightthickness=1, highlightbackground=BORDER,
                            highlightcolor=BORDER, padx=8, pady=6)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        self.text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        vsb.grid(row=1, column=1, sticky="ns", pady=(8, 0))
        self.text.configure(state="normal")
        self.text.insert("1.0", json.dumps(result, ensure_ascii=False, indent=2))
        self.text.configure(state="disabled")

        buttons = ttk.Frame(body)
        buttons.grid(row=2, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Ekspor JSON…", command=self._export_json).grid(
            row=0, column=0, padx=(0, 6))
        ttk.Button(buttons, text="Ekspor CSV…", command=self._export_csv).grid(
            row=0, column=1, padx=(0, 6))
        ttk.Button(buttons, text="Tutup", command=self.destroy).grid(
            row=0, column=2)

        self.grab_set()

    def _export_json(self):
        export_result(self, self.result, "json")

    def _export_csv(self):
        export_result(self, self.result, "csv")
