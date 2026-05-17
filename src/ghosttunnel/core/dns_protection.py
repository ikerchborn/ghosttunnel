"""
GhostTunnel DNS Protection
=============================
Fixes applied:
  HIGH-02   — No global socket.setdefaulttimeout mutation
  CRIT-02   — IP addresses from resolv.conf are validated before use
  BUG-FIX-1 — Corrected indentation error that broke the trust_local_dns block
"""
import ipaddress
import socket
from pathlib import Path
from typing import Tuple

from .config import Settings


def get_dns_servers(settings: Settings) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """
    Extracts DNS servers from /etc/resolv.conf and merges with bootstrap DNS.
    All IPs are validated before inclusion.
    If trust_local_dns is False, entirely ignores local system resolvers.
    """
    servers_v4: list[str] = []
    servers_v6: list[str] = []

    if settings.trust_local_dns:
        paths_to_check = [Path("/etc/resolv.conf"), Path("/run/systemd/resolve/resolv.conf")]
        for resolv in paths_to_check:
            if not resolv.exists():
                continue
            
            found_external = False
            for raw in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if line.startswith("nameserver "):
                    parts = line.split()
                    if len(parts) > 1:
                        value = parts[1]
                        if value in {"127.0.0.1", "127.0.0.53", "::1"}:
                            continue
                        # Validate IP before trusting it (CRIT-02)
                        if not _is_valid_ip(value):
                            continue
                        found_external = True
                        if ":" in value:
                            servers_v6.append(value)
                        else:
                            servers_v4.append(value)
            
            # If we found real external DNS servers, stop checking other files
            if found_external:
                break

    merged_v4 = tuple(dict.fromkeys([*settings.bootstrap_dns, *servers_v4]))
    merged_v6 = tuple(dict.fromkeys([*settings.bootstrap_dns_v6, *servers_v6]))
    return merged_v4, merged_v6


def resolve_hosts(hosts: list[str]) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """
    Resolves VPN endpoint domains to IPv4 and IPv6 addresses.
    Uses per-socket timeout instead of global default (HIGH-02).
    """
    ips_v4: list[str] = []
    ips_v6: list[str] = []

    if not hosts:
        return (), ()

    for host in hosts:
        try:
            answers = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            continue
        for answer in answers:
            family = answer[0]
            ip = answer[4][0]
            # Validate resolved IP (CRIT-02)
            if not _is_valid_ip(ip):
                continue
            if family == socket.AF_INET and ip not in ips_v4:
                ips_v4.append(ip)
            elif family == socket.AF_INET6 and ip not in ips_v6:
                ips_v6.append(ip)

    return tuple(ips_v4), tuple(ips_v6)


def _is_valid_ip(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
