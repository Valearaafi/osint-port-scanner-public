"""Lapisan query penyimpanan hasil scan di atas DatabaseManager.

Pembungkus tipis — tidak menduplikasi logika database; skema tabel tetap
milik database/models.py. Port yang terbuka disimpan sebagai hasil scan,
BUKAN sebagai baris vulnerabilities.
"""

import json
from typing import Any, Dict, Optional

from database.models import DatabaseManager

# Indeks kolom 'results' pada SELECT * di get_scan_by_id (urutan kolom
# scan_sessions: id, target, scan_type, timestamp, results, risk_score,
# status, duration).
RESULTS_COLUMN_INDEX = 4


def save_scan_session_result(
    db: DatabaseManager,
    result: Dict[str, Any],
    scan_type: Optional[str] = None,
    status: str = "completed",
) -> int:
    """Simpan hasil scan terstruktur sebagai sesi baru.

    scan_type diambil dari result['scan_type'] bila tidak diberikan.
    status: 'completed', 'failed', atau 'cancelled'.
    """
    target = str(result.get("target", ""))
    scan_type = scan_type or str(result.get("scan_type", "scan"))
    risk_score = int(result.get("risk_score") or 0)
    duration = float(result.get("duration") or 0.0)
    return db.save_scan_session(
        target,
        scan_type,
        result,
        risk_score=risk_score,
        duration=duration,
        status=status,
    )


def load_scan_session_result(
    db: DatabaseManager, session_id: int
) -> Optional[Dict[str, Any]]:
    """Muat hasil scan tersimpan berdasarkan ID sesi; None bila tak ada."""
    row = db.get_scan_by_id(session_id)
    if row is None:
        return None
    try:
        return json.loads(row[RESULTS_COLUMN_INDEX])
    except (TypeError, json.JSONDecodeError):
        return None
