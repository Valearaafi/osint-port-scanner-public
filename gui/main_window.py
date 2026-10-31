"""Jendela utama OSINT Port Scanner — Tahap 2: GUI fungsional."""

import os
import sys
import time
import tkinter as tk
from tkinter import messagebox, ttk

from config.settings import Config
from database.models import DatabaseManager
from database.queries import save_scan_session_result
from gui.scan_tabs import (DnsLookupTab, HistoryTab, IpLookupTab,
                           PortScannerTab, WhoisLookupTab, export_result)
from gui.settings_dialog import SettingsDialog
from gui.theme import apply_theme
from gui.worker import TaskRunner

APP_NAME = "OSINT Port Scanner"
APP_VERSION = "0.3.0"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _default_data_dir():
    """Direktori data (config.json, scans.db).

    Executable PyInstaller: %LOCALAPPDATA%\\OSINT Port Scanner (fallback:
    direktori aplikasi di home pengguna) — jangan pernah menulis ke direktori
    instalasi atau direktori ekstraksi sementara. Dari source: PROJECT_ROOT.
    """
    if getattr(sys, "frozen", False):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        data_dir = os.path.join(base, "OSINT Port Scanner")
        os.makedirs(data_dir, exist_ok=True)
        return data_dir
    return PROJECT_ROOT


class MainWindow:
    """Jendela utama: header, target bersama, 5 tab, menu, dan bilah status."""

    def __init__(self, config_path=None, db_path=None):
        default_dir = _default_data_dir()
        self.config = Config(config_path or os.path.join(default_dir, "config.json"))
        self.db = DatabaseManager(db_path or os.path.join(default_dir, "scans.db"))

        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.geometry("1000x700")
        self.root.minsize(860, 580)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        apply_theme(self.root)

        self.runner = TaskRunner(self.root)
        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Siap.")
        self._last_result = None

        self._build_menu()
        self._build_layout()

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        menu_file = tk.Menu(menubar, tearoff=0)
        menu_file.add_command(label="Ekspor JSON…", command=self._export_json)
        menu_file.add_command(label="Ekspor CSV…", command=self._export_csv)
        menu_file.add_separator()
        menu_file.add_command(label="Keluar", command=self._on_close)
        menubar.add_cascade(label="Berkas", menu=menu_file)

        menu_tools = tk.Menu(menubar, tearoff=0)
        menu_tools.add_command(label="Pengaturan…", command=self._open_settings)
        menubar.add_cascade(label="Alat", menu=menu_tools)

        menu_help = tk.Menu(menubar, tearoff=0)
        menu_help.add_command(label="Tentang…", command=self._show_about)
        menubar.add_cascade(label="Bantuan", menu=menu_help)

        self.root.config(menu=menubar)

    def _build_layout(self):
        header = ttk.Frame(self.root, padding=(14, 14, 14, 4))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").grid(
            row=0, column=0, sticky="w")
        ttk.Label(header, text=f"versi {APP_VERSION}",
                  style="Muted.TLabel").grid(row=0, column=1, sticky="e")
        ttk.Label(
            header,
            text="Pemeriksaan domain, DNS, WHOIS, dan port TCP — "
            "gunakan hanya pada sistem yang Anda miliki atau miliki izinnya.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        target_row = ttk.Frame(self.root, padding=(14, 10, 14, 8))
        target_row.grid(row=1, column=0, sticky="ew")
        target_row.columnconfigure(1, weight=1)
        ttk.Label(target_row, text="Target:").grid(row=0, column=0, sticky="w",
                                                   padx=(0, 8))
        self.target_entry = ttk.Entry(target_row, textvariable=self.target_var)
        self.target_entry.grid(row=0, column=1, sticky="ew")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=2, column=0, sticky="nsew", padx=14)

        self.ip_tab = IpLookupTab(self.notebook, self.config, self.runner,
                                  self.target_var, self._set_status,
                                  self._report_result)
        self.dns_tab = DnsLookupTab(self.notebook, self.config, self.runner,
                                    self.target_var, self._set_status,
                                    self._report_result)
        self.whois_tab = WhoisLookupTab(self.notebook, self.config, self.runner,
                                        self.target_var, self._set_status,
                                        self._report_result)
        self.port_tab = PortScannerTab(self.notebook, self.config, self.runner,
                                       self.target_var, self._set_status,
                                       self._report_result)
        self.history_tab = HistoryTab(self.notebook, self.db, self._set_status)

        self.notebook.add(self.ip_tab, text="IP Lookup")
        self.notebook.add(self.dns_tab, text="DNS Lookup")
        self.notebook.add(self.whois_tab, text="WHOIS Lookup")
        self.notebook.add(self.port_tab, text="Port Scanner")
        self.notebook.add(self.history_tab, text="Riwayat")
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        status_bar = ttk.Frame(self.root, padding=(14, 6))
        status_bar.grid(row=3, column=0, sticky="ew")
        status_bar.columnconfigure(0, weight=1)
        ttk.Separator(status_bar, orient="horizontal").grid(
            row=0, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(status_bar, textvariable=self.status_var,
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w")

        self.root.rowconfigure(2, weight=1)
        self.root.columnconfigure(0, weight=1)

    def _set_status(self, text):
        self.status_var.set(text)

    def _report_result(self, result, status):
        """Simpan hasil ke riwayat (bila auto_save) dan segarkan tab Riwayat."""
        self._last_result = result
        if not self.config.get("ui_settings.auto_save", True):
            return
        try:
            save_scan_session_result(self.db, result, status=status)
        except Exception as exc:
            self._set_status(f"Gagal menyimpan riwayat: {exc}")
            return
        self.history_tab.refresh()

    def _export_json(self):
        if self._last_result is None:
            messagebox.showinfo("Belum ada hasil",
                                "Jalankan pemindaian terlebih dahulu.",
                                parent=self.root)
            return
        export_result(self.root, self._last_result, "json", self._set_status)

    def _export_csv(self):
        if self._last_result is None:
            messagebox.showinfo("Belum ada hasil",
                                "Jalankan pemindaian terlebih dahulu.",
                                parent=self.root)
            return
        export_result(self.root, self._last_result, "csv", self._set_status)

    def _on_tab_changed(self, _event):
        if self.notebook.select() == str(self.history_tab):
            self.history_tab.refresh()

    def _open_settings(self):
        SettingsDialog(self.root, self.config).show()

    def _show_about(self):
        messagebox.showinfo(
            "Tentang",
            f"{APP_NAME} — versi {APP_VERSION}\n\n"
            "Alat pengumpulan informasi domain/DNS/WHOIS dan pemeriksaan "
            "port TCP.\n"
            "Gunakan hanya pada sistem yang Anda miliki atau dengan izin "
            "tertulis.",
            parent=self.root,
        )

    def _on_close(self):
        if self.runner.busy:
            if not messagebox.askyesno(
                    "Keluar",
                    "Pemindaian masih berjalan. Batalkan dan keluar?",
                    parent=self.root):
                return
            self.runner.cancel()
            # Pompa event loop sebentar agar hasil "dibatalkan" sempat
            # diproses (dan tersimpan ke riwayat) sebelum jendela ditutup.
            deadline = time.monotonic() + 2.0
            while self.runner.busy and time.monotonic() < deadline:
                try:
                    self.root.update()
                except tk.TclError:
                    break
                time.sleep(0.02)
        self.runner.wait(2.0)
        self.runner.shutdown()
        self.root.destroy()

    def run(self):
        self.root.mainloop()
