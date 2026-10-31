"""WHOIS lookup via protokol teks TCP port 43 (tanpa library pihak ketiga).

Alur: query whois.iana.org untuk mendapatkan server registry TLD, lalu
query server tersebut. Respons dikembalikan MENTAH — formatnya bervariasi
antar registrar sehingga tidak dijanjikan data registrasi lengkap.
"""

import socket
from typing import Dict, Optional

IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43


class WhoisError(Exception):
    """Kegagalan WHOIS: domain tidak valid, timeout, koneksi gagal."""


def _query_whois(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _extract_referral(iana_response: str) -> Optional[str]:
    for line in iana_response.splitlines():
        stripped = line.strip()
        for prefix in ("refer:", "whois:"):
            if stripped.lower().startswith(prefix):
                value = stripped.split(":", 1)[1].strip()
                if value and value.lower() != IANA_SERVER:
                    return value
    return None


def whois_lookup(domain: str, timeout: float = 10.0) -> Dict:
    """Lakukan WHOIS untuk domain.

    Mengembalikan {'domain', 'server', 'raw_response', 'error'}.
    error berisi None bila respons mentah berhasil diperoleh; kegagalan
    koneksi/timeout menghasilkan WhoisError dengan pesan jelas.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise WhoisError("Domain kosong.")

    domain = domain.strip().lower().rstrip(".")
    if " " in domain or "/" in domain or "." not in domain:
        raise WhoisError(f"Domain tidak valid: {domain!r}.")

    try:
        iana_response = _query_whois(IANA_SERVER, domain, timeout)
    except socket.timeout:
        raise WhoisError(f"WHOIS timeout ({timeout}s) saat menghubungi {IANA_SERVER}.") from None
    except OSError as error:
        raise WhoisError(f"Koneksi ke {IANA_SERVER} gagal: {error}") from None

    server = _extract_referral(iana_response)
    if not server:
        return {
            "domain": domain,
            "server": IANA_SERVER,
            "raw_response": iana_response,
            "error": "IANA tidak memberikan rujukan server WHOIS untuk TLD ini.",
        }

    try:
        raw_response = _query_whois(server, domain, timeout)
    except socket.timeout:
        raise WhoisError(f"WHOIS timeout ({timeout}s) saat menghubungi {server}.") from None
    except OSError as error:
        raise WhoisError(f"Koneksi ke server WHOIS {server} gagal: {error}") from None

    if not raw_response.strip():
        return {
            "domain": domain,
            "server": server,
            "raw_response": raw_response,
            "error": f"Server {server} mengembalikan respons kosong.",
        }

    return {"domain": domain, "server": server, "raw_response": raw_response, "error": None}
