"""Menjalankan tugas scanner di worker thread tanpa memblokir event loop Tk.

Pola: worker thread -> queue.Queue -> root.after(poll). Widget hanya
disentuh dari main thread lewat callback yang dipanggil di _poll().
"""

import queue
import threading
import traceback
import tkinter as tk


def _worker_target(q, target_fn, progress_cb, token):
    """Badan worker: tanpa closure atas TaskRunner (hindari siklus referensi)."""
    try:
        result = target_fn(progress_cb, token)
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc()}"
        q.put(("error", detail))
    else:
        q.put(("done", result))


class _TaskThread(threading.Thread):
    """Thread yang melepas _target/_args saat selesai.

    Tanpa ini, Thread menahan closure target selamanya dan membentuk
    siklus dengan TaskRunner/tab — finalisasi objek Tk bisa terjadi di
    thread worker dan merusak interpreter Tcl.
    """

    def run(self):
        try:
            if self._target is not None:
                self._target(*self._args, **self._kwargs)
        finally:
            del self._target, self._args, self._kwargs


class TaskRunner:
    """Menjalankan SATU tugas pada satu waktu; menolak tugas baru saat sibuk."""

    POLL_INTERVAL_MS = 50

    def __init__(self, root: tk.Misc):
        self._root = root
        self._queue = queue.Queue()
        self._thread = None
        self._after_id = None
        self._dead = False
        self._cancel_token = None
        self._on_done = None
        self._on_error = None
        self._on_progress = None
        self.busy = False

    def start(self, target, on_done, on_error, on_progress=None,
              cancel_token=None) -> bool:
        """Jalankan target(progress_cb, cancel_token) di worker thread.

        Kembalikan False bila masih ada tugas berjalan (tidak ada tugas ganda).
        """
        if self.busy:
            return False
        self.busy = True
        self._dead = False
        self._cancel_token = cancel_token
        self._on_done = on_done
        self._on_error = on_error
        self._on_progress = on_progress
        self._after_id = self._root.after(self.POLL_INTERVAL_MS, self._poll)

        # Callback progress dari scanner dipanggil di thread worker —
        # bungkus agar dikirim lewat queue dan hanya dijalankan di
        # main thread (widget Tk tidak boleh disentuh dari thread lain).
        q = self._queue
        progress_cb = None
        if on_progress is not None:
            def progress_cb(*args):
                q.put(("progress", args))

        self._thread = _TaskThread(
            target=_worker_target,
            args=(q, target, progress_cb, cancel_token),
            name="scan-worker",
            daemon=True,
        )
        self._thread.start()
        return True

    def cancel(self) -> None:
        """Teruskan pembatalan ke token tugas yang sedang berjalan."""
        token = self._cancel_token
        if token is not None:
            token.cancel()

    def shutdown(self) -> None:
        """Hentikan polling dan buang sisa tugas saat jendela ditutup.

        Membatalkan callback after() yang tertunda sehingga tidak ada
        lagi pemanggilan _poll setelah window dihancurkan (sumber noise
        'invalid command name ..._poll').
        """
        self._dead = True
        if self._after_id is not None:
            try:
                self._root.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        self._finish()

    def wait(self, timeout: float = None) -> None:
        """Tunggu thread worker selesai (opsional dengan batas waktu).

        Pastikan dipanggil sebelum objek yang dipegang worker (tab,
        variabel Tk) dibebaskan dari main thread, agar finalisasi tidak
        pernah terjadi di thread worker.
        """
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _finish(self) -> None:
        self.busy = False
        self._cancel_token = None
        self._on_done = None
        self._on_error = None
        self._on_progress = None

    def _cancel_timer(self, pending) -> None:
        """Batalkan timer after() yang belum sempat berjalan (bila ada)."""
        if pending is None:
            return
        try:
            self._root.after_cancel(pending)
        except tk.TclError:
            pass  # timer sudah berjalan/berakhir — tidak ada yang dibatalkan

    def _poll(self) -> None:
        """Pompa antrean hasil dari worker thread (dipanggil lewat root.after).

        TkError ditangkap: setelah jendela ditutup, sisa antrean dibuang
        dan tidak ada widget yang disentuh. Timer yang tidak terpakai
        selalu dibatalkan agar tidak memanggil _poll setelah window mati.
        """
        pending, self._after_id = self._after_id, None
        if not self.busy:
            self._cancel_timer(pending)
            return
        try:
            self._drain()
        except tk.TclError:
            self._finish()
            self._cancel_timer(pending)
            return
        if self.busy and not self._dead:
            try:
                alive = self._root.winfo_exists()
            except tk.TclError:
                alive = False
            if alive:
                self._cancel_timer(pending)
                try:
                    self._after_id = self._root.after(self.POLL_INTERVAL_MS,
                                                      self._poll)
                except tk.TclError:
                    self._finish()
                return
            self._finish()
        self._cancel_timer(pending)

    def _drain(self) -> None:
        while self.busy:
            try:
                kind, payload = self._queue.get_nowait()
            except queue.Empty:
                return
            if kind == "progress":
                if self._on_progress is not None:
                    self._on_progress(*payload)
                continue
            if kind == "done":
                callback = self._on_done
                self._finish()
            else:  # kind == "error"
                callback = self._on_error
                self._finish()
            if callback is not None:
                try:
                    callback(payload)
                except tk.TclError:
                    pass
