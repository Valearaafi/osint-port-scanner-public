"""Tema visual OSINT Port Scanner — palet gelap cybersecurity.

Semua warna dan font antarmuka terpusat di sini; modul lain memakai
token ini dan style ttk bernama, bukan warna hardcoded. Basis: tema
'clam' bawaan Tk — satu-satunya tema bawaan yang bisa diwarnai penuh
dan berperilaku identik dari source maupun exe PyInstaller, tanpa
dependency tambahan.
"""

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

BG = "#101318"
PANEL = "#191E25"
INPUT = "#141920"
BORDER = "#303844"
TEXT = "#E4E8ED"
MUTED = "#929BA7"
ACCENT = "#7396B5"
ACCENT_ACTIVE = "#86A6C2"
ACCENT_PRESSED = "#5F7F9C"
SURFACE_ACTIVE = "#232B35"
SELECT_BG = "#24313E"
DISABLED_FG = "#5A6472"

STATUS_OPEN = "#80A88B"
STATUS_CLOSED = "#C87979"
STATUS_UNKNOWN = "#D2AD70"

UI_FONT = "Segoe UI"
MONO_FONT = "Consolas"

PAD_MAIN = 14
PAD_TAB = 12


def _families(root):
    return set(tkfont.families(root))


def apply_theme(root):
    """Terapkan palet gelap ke seluruh widget ttk dari interpreter ini.

    Panggil SEKALI setelah tk.Tk() dibuat dan sebelum widget dibangun,
    agar style terpasang pada semua widget.
    """
    families = _families(root)
    ui_family = UI_FONT if UI_FONT in families else \
        tkfont.nametofont("TkDefaultFont").actual("family")
    mono_family = MONO_FONT if MONO_FONT in families else \
        tkfont.nametofont("TkFixedFont").actual("family")

    for name, family in (("TkDefaultFont", ui_family),
                         ("TkTextFont", ui_family),
                         ("TkHeadingFont", ui_family),
                         ("TkMenuFont", ui_family),
                         ("TkTooltipFont", ui_family),
                         ("TkCaptionFont", ui_family),
                         ("TkSmallCaptionFont", ui_family),
                         ("TkIconFont", ui_family),
                         ("TkFixedFont", mono_family)):
        tkfont.nametofont(name).configure(family=family)

    root.configure(background=BG)
    root.option_add("*Menu.background", PANEL)
    root.option_add("*Menu.foreground", TEXT)
    root.option_add("*Menu.activeBackground", ACCENT)
    root.option_add("*Menu.activeForeground", BG)
    root.option_add("*Menu.borderWidth", 1)
    root.option_add("*Menu.relief", "flat")
    root.option_add("*Text.selectBackground", SELECT_BG)
    root.option_add("*Text.selectForeground", TEXT)
    root.option_add("*Text.insertBackground", TEXT)
    root.option_add("*TCombobox*Listbox.background", PANEL)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT_BG)
    root.option_add("*TCombobox*Listbox.selectForeground", TEXT)

    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG, foreground=TEXT,
                    troughcolor=INPUT, bordercolor=BORDER,
                    insertcolor=TEXT, selectbackground=SELECT_BG,
                    selectforeground=TEXT)

    # --- Label & frame ---
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("Title.TLabel", background=BG, foreground=TEXT,
                    font=(ui_family, 15, "bold"))
    style.configure("Subtitle.TLabel", background=BG, foreground=MUTED,
                    font=(ui_family, 9))
    style.configure("TabHeader.TLabel", background=BG, foreground=TEXT,
                    font=(ui_family, 12, "bold"))
    style.configure("TabDesc.TLabel", background=BG, foreground=MUTED,
                    font=(ui_family, 9))

    # --- Tombol ---
    style.configure("TButton", background=PANEL, foreground=TEXT,
                    bordercolor=BORDER, borderwidth=1, relief="flat",
                    padding=(12, 5), focusthickness=1, focuscolor=ACCENT)
    style.map("TButton",
              background=[("pressed", SURFACE_ACTIVE),
                          ("active", SURFACE_ACTIVE),
                          ("disabled", PANEL)],
              foreground=[("disabled", DISABLED_FG)],
              bordercolor=[("focus", ACCENT), ("disabled", BORDER)])

    style.configure("Accent.TButton", background=ACCENT, foreground=BG,
                    bordercolor=ACCENT, borderwidth=1, relief="flat",
                    padding=(12, 5), focusthickness=1, focuscolor=BG)
    style.map("Accent.TButton",
              background=[("pressed", ACCENT_PRESSED),
                          ("active", ACCENT_ACTIVE),
                          ("disabled", "#26313D")],
              foreground=[("disabled", DISABLED_FG)],
              bordercolor=[("disabled", "#26313D")])

    # --- Input ---
    for widget in ("TEntry", "TSpinbox"):
        style.configure(widget, fieldbackground=INPUT, foreground=TEXT,
                        background=INPUT, bordercolor=BORDER, borderwidth=1,
                        insertcolor=TEXT, lightcolor="#2A3440",
                        darkcolor="#2A3440", padding=4,
                        font=(mono_family, 10))
        style.map(widget,
                  bordercolor=[("focus", ACCENT), ("disabled", BORDER)],
                  lightcolor=[("focus", ACCENT)],
                  darkcolor=[("focus", ACCENT)],
                  fieldbackground=[("disabled", PANEL)],
                  foreground=[("disabled", DISABLED_FG)])

    style.configure("TCombobox", fieldbackground=INPUT, foreground=TEXT,
                    background=PANEL, bordercolor=BORDER, borderwidth=1,
                    arrowcolor=MUTED, insertcolor=TEXT, padding=4)
    style.map("TCombobox",
              fieldbackground=[("readonly", INPUT), ("disabled", PANEL)],
              foreground=[("disabled", DISABLED_FG)],
              bordercolor=[("focus", ACCENT)],
              arrowcolor=[("disabled", DISABLED_FG)])

    # --- Notebook (tab) ---
    style.configure("TNotebook", background=BG, borderwidth=0,
                    tabmargins=(8, 8, 8, 0))
    style.configure("TNotebook.Tab", background=BG, foreground=MUTED,
                    borderwidth=0, padding=(14, 7), focusthickness=0,
                    lightcolor=BG, darkcolor=BG, bordercolor=BG)
    style.map("TNotebook.Tab",
              background=[("selected", PANEL), ("active", "#161C23")],
              foreground=[("selected", TEXT), ("active", TEXT)],
              lightcolor=[("selected", ACCENT)])

    # --- Progressbar ---
    style.configure("Horizontal.TProgressbar", troughcolor=INPUT,
                    background=ACCENT, bordercolor=BORDER, borderwidth=1,
                    lightcolor=ACCENT, darkcolor=ACCENT)

    # --- Separator & scrollbar ---
    style.configure("TSeparator", background=BORDER)
    style.configure("TScrollbar", background="#2A3440", troughcolor=BG,
                    bordercolor=BG, arrowcolor=MUTED, relief="flat",
                    borderwidth=0)
    style.map("TScrollbar", background=[("active", "#36424F")])

    # --- Checkbutton (dialog pengaturan) ---
    style.configure("TCheckbutton", background=BG, foreground=TEXT)
    style.map("TCheckbutton", background=[("active", BG)])

    # --- Tabel ---
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, bordercolor=BORDER, borderwidth=1,
                    relief="flat", rowheight=26, font=(mono_family, 10))
    style.map("Treeview",
              background=[("selected", SELECT_BG)],
              foreground=[("selected", TEXT)])
    style.configure("Treeview.Heading", background=BG, foreground=MUTED,
                    bordercolor=BORDER, borderwidth=1, relief="flat",
                    padding=(8, 6), font=(ui_family, 9))
    style.map("Treeview.Heading",
              background=[("active", "#1B2129")],
              foreground=[("active", TEXT)])


def apply_status_tags(tree):
    """Daftarkan tag warna status pada Treeview untuk pewarnaan baris."""
    for tag, color in (("open", STATUS_OPEN),
                       ("closed", STATUS_CLOSED),
                       ("filtered", STATUS_UNKNOWN),
                       ("success", STATUS_OPEN),
                       ("warning", STATUS_UNKNOWN),
                       ("error", STATUS_CLOSED),
                       ("muted", MUTED)):
        tree.tag_configure(tag, foreground=color)
