"""Utilitas validasi dan resolusi alamat IP / hostname."""

import ipaddress
import re
import socket
from typing import Dict, List

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class InvalidTargetError(ValueError):
    """Target kosong atau formatnya bukan hostname maupun alamat IP yang valid."""


class ResolutionError(Exception):
    """Resolusi DNS gagal (NXDOMAIN, timeout, atau kegagalan resolver)."""


def validate_target(target: str) -> str:
    """Kembalikan 'ipv4', 'ipv6', atau 'hostname' bila target valid.

    Keberhasilan validasi hanya berarti formatnya dapat diproses — bukan
    bukti bahwa host aman atau dapat dijangkau.
    """
    if not isinstance(target, str) or not target.strip():
        raise InvalidTargetError("Target kosong. Masukkan alamat IP atau nama domain.")

    target = target.strip()

    try:
        ip = ipaddress.ip_address(target)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass

    if _HOSTNAME_RE.fullmatch(target):
        if target.split(".")[-1].isdigit():
            raise InvalidTargetError(f"Format alamat tidak dikenali: {target!r}.")
        return "hostname"

    raise InvalidTargetError(f"Format alamat tidak dikenali: {target!r}.")


def resolve_hostname(hostname: str) -> Dict[str, List[str]]:
    """Resolusi hostname via resolver sistem menjadi daftar IPv4 dan IPv6.

    Kegagalan apa pun (NXDOMAIN, resolver tidak merespons, dll.) menghasilkan
    ResolutionError — tidak ada alamat yang dibuat-buat.
    """
    if not isinstance(hostname, str) or not hostname.strip():
        raise ResolutionError("Nama host kosong.")

    hostname = hostname.strip()
    results: Dict[str, List[str]] = {"ipv4": [], "ipv6": []}

    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ResolutionError(f"Gagal meresolusi {hostname!r}: {e}") from e

    for family, _, _, _, sockaddr in infos:
        address = sockaddr[0]
        if family == socket.AF_INET and address not in results["ipv4"]:
            results["ipv4"].append(address)
        elif family == socket.AF_INET6 and address not in results["ipv6"]:
            results["ipv6"].append(address)

    if not results["ipv4"] and not results["ipv6"]:
        raise ResolutionError(f"Tidak ada alamat IP ditemukan untuk {hostname!r}.")

    return results


def resolve_target(target: str) -> Dict[str, object]:
    """Resolusi target (IP atau hostname) menjadi alamat siap pakai.

    Mengembalikan {'kind', 'target', 'ipv4', 'ipv6'}; untuk hostname juga
    menyertakan 'hostname'. Memakai resolver sistem, tanpa layanan pihak ketiga.
    """
    kind = validate_target(target)

    if kind == "ipv4":
        return {"kind": kind, "target": target.strip(), "ipv4": [target.strip()], "ipv6": []}
    if kind == "ipv6":
        return {"kind": kind, "target": target.strip(), "ipv4": [], "ipv6": [target.strip()]}

    addresses = resolve_hostname(target.strip())
    return {"kind": kind, "target": target.strip(), "hostname": target.strip(), **addresses}
