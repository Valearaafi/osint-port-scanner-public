"""Tabel hasil yang bisa diurutkan dengan klik pada judul kolom."""

import tkinter as tk
from tkinter import ttk
from typing import Any, Dict, List, Optional, Sequence, Tuple

from gui.theme import apply_status_tags


def sort_key(value: Any) -> Tuple:
    """Kunci pengurutan yang aman untuk campuran angka, teks, dan None.

    Angka diurutkan secara numerik (None dianggap kosong), teks
    case-insensitive — hindari error saat membandingkan tipe campuran.
    """
    if value is None:
        value = ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (0, float(value), "")
    return (1, str(value).lower(), str(value))


class SortableTable(ttk.Frame):
    """Treeview dengan satu kolom terpilih, dukungan klik-judul untuk sortir."""

    def __init__(self, master, columns: Sequence[str],
                 headings: Optional[Sequence[str]] = None,
                 column_widths: Optional[Dict[str, int]] = None,
                 on_select=None):
        super().__init__(master)
        self._columns = list(columns)
        self._headings = dict(zip(
            self._columns, headings if headings is not None else self._columns))
        self._rows: List[Tuple[Tuple, Any]] = []
        self._item_ids: Dict[str, Any] = {}
        self._sort_column = None
        self._sort_descending = False
        self._on_select = on_select

        self.tree = ttk.Treeview(self, columns=self._columns, show="headings",
                                 selectmode="browse")
        apply_status_tags(self.tree)
        for col in self._columns:
            self.tree.heading(col, text=self._headings[col],
                              command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=(column_widths or {}).get(col, 110),
                             stretch=True, anchor="w")
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        if on_select is not None:
            self.tree.bind("<<TreeviewSelect>>", lambda _e: on_select())

    def set_rows(self, rows: Sequence[Sequence],
                 ids: Optional[Sequence] = None,
                 tags: Optional[Sequence] = None) -> None:
        """Ganti seluruh isi tabel; urutan sortir aktif dipertahankan.

        ids (opsional) memetakan tiap baris ke nilai identitas (mis. ID
        sesi database) yang bisa diambil lewat selected_id(). tags
        (opsional) memetakan tiap baris ke tag pewarnaan baris.
        """
        if ids is None:
            ids = [None] * len(rows)
        if tags is None:
            tags = [() for _ in rows]
        self._rows = list(zip([tuple(r) for r in rows], ids,
                              [tuple(t) if t else () for t in tags]))
        self._refresh()

    def clear(self) -> None:
        self._rows = []
        self._item_ids = {}
        self._refresh()

    def get_values(self) -> List[Tuple]:
        """Isi tabel dalam urutan tampil saat ini."""
        return [values for values, _id, _tags in self._rows]

    def selected_values(self) -> Optional[Tuple]:
        """Nilai baris terpilih, atau None bila tidak ada pilihan."""
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")

    def selected_id(self) -> Any:
        """Identitas baris terpilih (dari argumen ids), atau None."""
        selection = self.tree.selection()
        if not selection:
            return None
        return self._item_ids.get(selection[0])

    def _refresh(self) -> None:
        self._item_ids = {}
        for item in self.tree.get_children():
            self.tree.delete(item)
        for values, row_id, tags in self._rows:
            item = self.tree.insert("", "end", values=values, tags=tags)
            self._item_ids[item] = row_id
        if self._sort_column is not None:
            self._apply_sort()
            self._update_heading()

    def _sort_by(self, column: str) -> None:
        if self._sort_column == column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = column
            self._sort_descending = False
        self._apply_sort()
        self._update_heading()

    def _apply_sort(self) -> None:
        idx = self._columns.index(self._sort_column)
        self._rows.sort(key=lambda pair: sort_key(pair[0][idx]),
                        reverse=self._sort_descending)
        self._item_ids = {}
        for item in self.tree.get_children():
            self.tree.delete(item)
        for values, row_id, tags in self._rows:
            item = self.tree.insert("", "end", values=values, tags=tags)
            self._item_ids[item] = row_id

    def _update_heading(self) -> None:
        for col in self._columns:
            base = self._headings[col]
            if col == self._sort_column:
                arrow = " \u25bc" if self._sort_descending else " \u25b2"
                self.tree.heading(col, text=base + arrow)
            else:
                self.tree.heading(col, text=base)
