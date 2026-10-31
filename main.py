# main.py
"""
OSINT Port Scanner - application entry point.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point for the application"""
    try:
        from gui.main_window import MainWindow

        app = MainWindow()
        app.run()

    except ImportError as e:
        error_msg = f"Modul yang dibutuhkan tidak ditemukan: {e}"
        print(error_msg, file=sys.stderr)
        _show_error("Kesalahan Import", error_msg)

    except Exception as e:
        error_msg = f"Gagal menjalankan aplikasi: {e}"
        print(error_msg, file=sys.stderr)
        _show_error("Kesalahan Startup", error_msg)


def _show_error(title: str, message: str) -> None:
    """Tampilkan dialog error bila tkinter tersedia; diam saja bila tidak."""
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except tk.TclError:
        pass


if __name__ == "__main__":
    main()