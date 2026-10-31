"""Pemeriksaan record DNS (A, AAAA, NS, MX).

Record NS dan MX tidak tersedia di standard library, sehingga memakai
dnspython yang melakukan query ke resolver sistem — bukan layanan pihak
ketiga. Hasil yang tidak tersedia tidak pernah dibuat-buat: kegagalan
(NXDOMAIN, timeout, respons kosong) dicatat di bagian 'errors'.
"""

from typing import Dict, List, Sequence

import dns.resolver

SUPPORTED_TYPES = ("A", "AAAA", "NS", "MX")


def _normalize_name(name: str) -> str:
    """Buang titik akhir DNS (kecuali untuk root)."""
    return name[:-1] if len(name) > 1 and name.endswith(".") else name


def _lookup_single(domain: str, record_type: str, lifetime: float) -> List[str]:
    answers = dns.resolver.resolve(domain, record_type, lifetime=lifetime)
    if record_type == "MX":
        pairs = sorted(
            (answer.preference, _normalize_name(str(answer.exchange))) for answer in answers
        )
        return [f"{pref} {exchange}" for pref, exchange in pairs]
    return sorted({_normalize_name(str(answer)) for answer in answers})


def _describe_dns_error(error: Exception) -> str:
    if isinstance(error, dns.resolver.NXDOMAIN):
        return "Domain tidak ditemukan (NXDOMAIN)."
    if isinstance(error, dns.resolver.NoAnswer):
        return "Tidak ada record untuk tipe ini."
    if isinstance(error, dns.resolver.NoNameservers):
        return "Server DNS tidak merespons."
    if isinstance(error, dns.resolver.Timeout):
        return "Waktu tunggu DNS habis."
    return f"Kegagalan DNS: {error}"


def lookup_records(
    domain: str,
    record_types: Sequence[str] = SUPPORTED_TYPES,
    timeout: float = 5.0,
) -> Dict:
    """Periksa record DNS domain.

    Mengembalikan {'domain', 'records': {tipe: [nilai]}, 'errors': {tipe: pesan}}.
    Tipe record yang gagal tidak muncul di 'records' — kegagalannya ada di
    'errors' dengan pesan yang jelas.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Domain kosong.")

    domain = domain.strip().rstrip(".")
    records: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}

    for record_type in record_types:
        if record_type not in SUPPORTED_TYPES:
            errors[record_type] = f"Tipe record tidak didukung: {record_type}."
            continue
        try:
            records[record_type] = _lookup_single(domain, record_type, timeout)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.resolver.Timeout, dns.exception.DNSException) as error:
            errors[record_type] = _describe_dns_error(error)

    return {"domain": domain, "records": records, "errors": errors}
