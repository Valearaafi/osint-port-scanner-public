"""Fungsi ekspor hasil pemindaian ke JSON/CSV.

Fungsi murni (tanpa ketergantungan Tk) agar mudah diuji. Tidak pernah
mengekspor API key — hasil scanner tidak memuat kredensial.
"""

import csv
import json
from typing import Any, Dict, List

CSV_PORT_COLUMNS = ["port", "status", "duration_ms", "error"]


def write_json_result(path: str, result: Dict[str, Any]) -> None:
    """Tulis hasil pemindaian sebagai JSON (UTF-8, tipe data dipertahankan)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)


def port_rows_for_csv(result: Any) -> List[Dict[str, Any]]:
    """Ambil daftar baris port dari hasil pemindaian TCP.

    ValueError bila result bukan hasil pemindaian port — ekspor CSV hanya
    bermakna untuk hasil port, bukan IP/DNS/WHOIS.
    """
    if not isinstance(result, dict) or result.get("scan_type") != "tcp_connect":
        raise ValueError(
            "Ekspor CSV hanya tersedia untuk hasil pemindaian port "
            "(IP/DNS/WHOIS hanya bisa diekspor sebagai JSON)."
        )
    ports = result.get("ports")
    if not isinstance(ports, list):
        raise ValueError("Hasil pemindaian port tidak memuat daftar port.")
    return ports


def write_csv_ports(path: str, result: Dict[str, Any]) -> None:
    """Tulis hasil pemindaian port sebagai CSV (UTF-8, header jelas)."""
    rows = port_rows_for_csv(result)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_PORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in CSV_PORT_COLUMNS})
