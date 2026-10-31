"""Dialog pengaturan aplikasi — terhubung ke Config, tanpa API key.

Hanya nilai yang didukung scanner yang bisa diubah; kunci API tidak
pernah ditampilkan di sini.
"""

import tkinter as tk
from tkinter import messagebox, ttk

from gui.theme import BG


class SettingsDialog(tk.Toplevel):
    """Dialog modal untuk pengaturan pemindaian; menyimpan lewat Config.set()."""

    def __init__(self, parent, config):
        super().__init__(parent)
        self.config = config
        self.title("Pengaturan")
        self.resizable(False, False)
        self.transient(parent)
        self.configure(background=BG)

        self.timeout_var = tk.StringVar(
            value=str(config.get("scan_settings.timeout", 5)))
        self.workers_var = tk.StringVar(
            value=str(config.get("scan_settings.max_threads", 50)))
        self.rate_var = tk.StringVar(
            value=str(config.get("scan_settings.rate_limit", 10)))
        self.rate_limiting_var = tk.BooleanVar(
            value=bool(config.get("security.rate_limiting", True)))

        body = ttk.Frame(self, padding=14)
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)

        ttk.Label(body, text="Pengaturan", style="TabHeader.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(body, text="Timeout pemindaian (detik):").grid(
            row=1, column=0, sticky="w", pady=4)
        ttk.Spinbox(body, from_=0.5, to=60.0, increment=0.5,
                    textvariable=self.timeout_var, width=8).grid(
            row=1, column=1, sticky="w", pady=4)

        ttk.Label(body, text="Jumlah worker maksimum:").grid(
            row=2, column=0, sticky="w", pady=4)
        ttk.Spinbox(body, from_=1, to=500, increment=1,
                    textvariable=self.workers_var, width=8).grid(
            row=2, column=1, sticky="w", pady=4)

        ttk.Label(body, text="Batas laju (port/detik, 0 = tanpa batas):").grid(
            row=3, column=0, sticky="w", pady=4)
        ttk.Spinbox(body, from_=0, to=1000, increment=1,
                    textvariable=self.rate_var, width=8).grid(
            row=3, column=1, sticky="w", pady=4)

        ttk.Checkbutton(body, text="Aktifkan pembatasan laju",
                        variable=self.rate_limiting_var).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(8, 2))

        ttk.Label(body, text="Kunci API tidak pernah ditampilkan di aplikasi ini.",
                  style="Muted.TLabel").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))

        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Simpan", style="Accent.TButton",
                   command=self._save).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(buttons, text="Batal", command=self.destroy).grid(
            row=0, column=1)

    def show(self):
        """Tampilkan sebagai dialog modal dan tunggu sampai ditutup."""
        self.wait_visibility()
        self.grab_set()
        self.wait_window()

    def _save(self):
        try:
            timeout = float(self.timeout_var.get())
            workers = int(self.workers_var.get())
            rate = int(self.rate_var.get())
        except ValueError:
            messagebox.showerror(
                "Nilai tidak valid",
                "Timeout, worker, dan batas laju harus berupa angka.",
                parent=self)
            return
        if not (0.5 <= timeout <= 60.0):
            messagebox.showerror("Nilai tidak valid",
                                 "Timeout harus antara 0,5 dan 60 detik.",
                                 parent=self)
            return
        if not (1 <= workers <= 500):
            messagebox.showerror("Nilai tidak valid",
                                 "Jumlah worker harus antara 1 dan 500.",
                                 parent=self)
            return
        if not (0 <= rate <= 1000):
            messagebox.showerror("Nilai tidak valid",
                                 "Batas laju harus antara 0 dan 1000.",
                                 parent=self)
            return
        self.config.set("scan_settings.timeout", timeout)
        self.config.set("scan_settings.max_threads", workers)
        self.config.set("scan_settings.rate_limit", rate)
        self.config.set("security.rate_limiting",
                        bool(self.rate_limiting_var.get()))
        self.destroy()
