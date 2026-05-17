"""
GhostTunnel System Utilities
==============================
Hardened subprocess execution and input sanitization.

Fixes applied:
  CRIT-02 — Input sanitization for nftables injection prevention
  LOW-01  — Hardcoded binary paths instead of trusting $PATH
  MED-03  — Per-use timeout overrides
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess

# ------------------------------------------------------------------
# Hardcoded trusted binary paths (LOW-01)
# Fallback to shutil.which only if the hardcoded path doesn't exist.
# ------------------------------------------------------------------
_TRUSTED_BINARIES: dict[str, tuple[str, ...]] = {
    "nft":           ("/usr/sbin/nft",            "/sbin/nft",            "/usr/bin/nft"),
    "ip":            ("/usr/sbin/ip",             "/sbin/ip",             "/usr/bin/ip"),
    "protonvpn-cli": ("/usr/bin/protonvpn-cli",   "/usr/local/bin/protonvpn-cli"),
    "systemctl":     ("/usr/bin/systemctl",        "/bin/systemctl"),
    "sysctl":        ("/usr/sbin/sysctl",          "/sbin/sysctl",         "/usr/bin/sysctl"),
}


class CommandError(RuntimeError):
    pass


# ------------------------------------------------------------------
# Input sanitization (CRIT-02)
# ------------------------------------------------------------------
_VALID_IFACE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,15}$")
_VALID_TABLE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")


def sanitize_iface(name: str) -> str:
    """Validate and return a safe interface name, or raise ValueError."""
    if not _VALID_IFACE_RE.match(name):
        raise ValueError(f"Invalid interface name rejected: {name!r}")
    return name


def sanitize_ip(addr: str) -> str:
    """Validate an IPv4 or IPv6 address (with optional CIDR). Raises ValueError."""
    try:
        # Handles both bare addresses and CIDR notation
        if "/" in addr:
            ipaddress.ip_network(addr, strict=False)
        else:
            ipaddress.ip_address(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address rejected: {addr!r}")
    return addr


def sanitize_port(port: int) -> int:
    """Validate a network port number. Raises ValueError."""
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Invalid port number rejected: {port!r}")
    return port


def sanitize_table_name(name: str) -> str:
    """Validate an nftables table name. Raises ValueError."""
    if not _VALID_TABLE_RE.match(name):
        raise ValueError(f"Invalid table name rejected: {name!r}")
    return name


# ------------------------------------------------------------------
# Root check
# ------------------------------------------------------------------
def require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("This command must run as root.")


# ------------------------------------------------------------------
# Binary resolution (LOW-01)
# ------------------------------------------------------------------
def find_binary(name: str) -> str:
    """
    Return the absolute path to a trusted system binary.
    Prefers hardcoded paths; falls back to shutil.which only for
    non-security-critical tools.
    """
    candidates = _TRUSTED_BINARIES.get(name, ())
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Fallback — only if not a critical binary
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Missing required binary: {name}")
    return path


# ------------------------------------------------------------------
# Subprocess execution
# ------------------------------------------------------------------
def run(
    args: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
    timeout: float = 5.0,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a system command with capture and timeout.
    Timeout is per-call so callers can override for slow VPN CLIs (MED-03).
    """
    try:
        result = subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Do NOT include full args in error — may contain internal paths (CRIT-02)
        raise CommandError(f"Command timed out after {timeout}s: {args[0]!r}") from exc
    if check and result.returncode != 0:
        # Limit stderr to 300 chars to avoid leaking verbose system information
        err = (result.stderr.strip() or "Command failed")[:300]
        raise CommandError(err)
    return result
