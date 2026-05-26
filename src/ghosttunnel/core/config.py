"""
GhostTunnel Configuration
===========================
Fixes applied:
  MED-02 — Type-validated config loading (rejects malformed values)
  CRIT-02 — Sanitization of all network-facing fields on load
  SEC-CFG-01 — Config file ownership validation before loading
  SEC-CFG-02 — Sanitization errors now drop the bad value instead of crashing
"""
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .system import sanitize_ip, sanitize_iface, sanitize_port, sanitize_table_name

logger = logging.getLogger(__name__)


def _safe_iface_hint(name: str) -> bool:
    """Return True if name is a valid interface prefix hint, False otherwise."""
    try:
        sanitize_iface(name)
        return True
    except ValueError:
        logger.warning("Dropping invalid VPN hint from config: %r", name)
        return False

DEFAULT_CONFIG_PATH = "/etc/ghosttunnel/config.json"

DEFAULT_VPN_HINTS = ("tun", "tap", "wg", "ppp", "proton", "pvpn", "nordlynx", "mullvad")
LAN_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
LAN_NETWORKS_V6 = ("fe80::/10", "fc00::/7")
BOOTSTRAP_DNS = ("1.1.1.1", "1.0.0.1", "9.9.9.9")
BOOTSTRAP_DNS_V6 = ("2606:4700:4700::1111", "2606:4700:4700::1001")
UDP_HANDSHAKE_PORTS = (500, 4500, 1194, 51820)
TCP_HANDSHAKE_PORTS = (443, 1194)

# Type specifications for config fields (MED-02)
_FIELD_TYPES: dict[str, type] = {
    "kill_switch": bool,
    "ipv6_block": bool,
    "auto_rotate": bool,
    "trust_local_dns": bool,
    "allow_lan": bool,
    "allow_forwarding": bool,
    "stealth_mode": bool,
    "monitor_poll_seconds": float,
    "table_name": str,
    "status_path": str,
}
_LIST_STR_FIELDS = {
    "vpn_priority", "vpn_hints", "lan_networks", "lan_networks_v6",
    "bootstrap_dns", "bootstrap_dns_v6", "custom_vpn_endpoints",
}
_LIST_INT_FIELDS = {"udp_handshake_ports", "tcp_handshake_ports"}


@dataclass(slots=True)
class Settings:
    # OPSEC specific features
    kill_switch: bool = True
    ipv6_block: bool = True
    auto_rotate: bool = False
    trust_local_dns: bool = False  # RED TEAM FIX: Do not trust DHCP DNS by default
    vpn_priority: list[str] = field(default_factory=lambda: ["protonvpn", "mullvad", "wireguard"])

    # Advanced features
    allow_lan: bool = False
    allow_forwarding: bool = False
    stealth_mode: bool = False  # Blocks ICMP, randomizes DNS, etc.

    # Internal parameters
    table_name: str = "ghosttunnel"
    status_path: str = "/run/ghosttunnel/status.json"
    monitor_poll_seconds: float = 5.0

    vpn_hints: list[str] = field(default_factory=lambda: list(DEFAULT_VPN_HINTS))
    lan_networks: list[str] = field(default_factory=lambda: list(LAN_NETWORKS))
    lan_networks_v6: list[str] = field(default_factory=lambda: list(LAN_NETWORKS_V6))
    bootstrap_dns: list[str] = field(default_factory=lambda: list(BOOTSTRAP_DNS))
    bootstrap_dns_v6: list[str] = field(default_factory=lambda: list(BOOTSTRAP_DNS_V6))
    udp_handshake_ports: list[int] = field(default_factory=lambda: list(UDP_HANDSHAKE_PORTS))
    tcp_handshake_ports: list[int] = field(default_factory=lambda: list(TCP_HANDSHAKE_PORTS))
    custom_vpn_endpoints: list[str] = field(default_factory=lambda: ["api.protonvpn.ch", "api.protonmail.ch"])

    @classmethod
    def load(cls, path: str = DEFAULT_CONFIG_PATH) -> "Settings":
        if not os.path.exists(path):
            return cls()

        # SEC-CFG-01: Validate config file is owned by root and not world-writable
        try:
            st = os.stat(path)
            if st.st_uid != 0:
                logger.error(
                    "Config file %s is not owned by root (uid=%d) — ignoring.",
                    path, st.st_uid,
                )
                return cls()
            if st.st_mode & 0o002:  # world-writable bit
                logger.error(
                    "Config file %s is world-writable — refusing to load (possible tampering).",
                    path,
                )
                return cls()
        except OSError as e:
            logger.error("Cannot stat config file %s: %s", path, e)
            return cls()

        try:
            with open(path, "r") as f:
                data = json.load(f)

            settings = cls()
            for key, value in data.items():
                if not hasattr(settings, key):
                    logger.warning("Ignoring unknown config key: %s", key)
                    continue
                validated = cls._validate_field(key, value)
                if validated is not None:
                    setattr(settings, key, validated)

            # Post-load sanitization of network-facing fields (CRIT-02)
            settings._sanitize_network_fields()
            return settings

        except Exception as e:
            logger.error("Failed to load config from %s: %s", path, e)
            return cls()

    def _sanitize_network_fields(self) -> None:
        """
        Validate all IPs, ports, and names that end up in nftables rules.
        SEC-CFG-02: Invalid values are silently dropped instead of raising,
        so a single bad entry doesn't abort the entire sanitization pass.
        """
        try:
            self.table_name = sanitize_table_name(self.table_name)
        except ValueError:
            logger.warning("Invalid table_name in config — resetting to default.")
            self.table_name = "ghosttunnel"

        def _safe_ip(ip: str) -> str | None:
            try:
                return sanitize_ip(ip)
            except ValueError:
                logger.warning("Dropping invalid IP from config: %r", ip)
                return None

        def _safe_port(p: int) -> int | None:
            try:
                return sanitize_port(p)
            except ValueError:
                logger.warning("Dropping invalid port from config: %r", p)
                return None

        self.lan_networks     = [r for r in (_safe_ip(ip) for ip in self.lan_networks)     if r is not None]
        self.lan_networks_v6  = [r for r in (_safe_ip(ip) for ip in self.lan_networks_v6)  if r is not None]
        self.bootstrap_dns    = [r for r in (_safe_ip(ip) for ip in self.bootstrap_dns)    if r is not None]
        self.bootstrap_dns_v6 = [r for r in (_safe_ip(ip) for ip in self.bootstrap_dns_v6) if r is not None]

        self.udp_handshake_ports = [r for r in (_safe_port(p) for p in self.udp_handshake_ports) if r is not None]
        self.tcp_handshake_ports = [r for r in (_safe_port(p) for p in self.tcp_handshake_ports) if r is not None]

        # VPN hints are used for interface name prefix matching — validate format
        self.vpn_hints = [h for h in self.vpn_hints if _safe_iface_hint(h)]

    @classmethod
    def _validate_field(cls, key: str, value: Any) -> Any:
        """Type-check a config value before assignment (MED-02)."""
        # Scalar type checks
        expected = _FIELD_TYPES.get(key)
        if expected is not None:
            if expected is float and isinstance(value, (int, float)):
                return float(value)
            if not isinstance(value, expected):
                logger.warning(
                    "Config key '%s' has wrong type %s (expected %s) — skipping.",
                    key, type(value).__name__, expected.__name__,
                )
                return None
            return value

        # List[str] checks
        if key in _LIST_STR_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                logger.warning("Config key '%s' must be list[str] — skipping.", key)
                return None
            return value

        # List[int] checks
        if key in _LIST_INT_FIELDS:
            if not isinstance(value, list) or not all(isinstance(v, int) for v in value):
                logger.warning("Config key '%s' must be list[int] — skipping.", key)
                return None
            return value

        return value   # Unknown fields handled upstream

    def save(self, path: str = DEFAULT_CONFIG_PATH) -> None:
        """
        Atomically write config with restricted permissions (0o600).

        Args:
            path: Target file path to write to.
        """
        try:
            dest = Path(path)
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = asdict(self)
            content = json.dumps(data, indent=4)
            # Use NamedTemporaryFile with a context manager for safe descriptor cleanup
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=str(dest.parent),
                prefix=".cfg-",
                suffix=".tmp",
                delete=False,
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(content)
                tmp_path = tmp_file.name
            os.chmod(tmp_path, 0o600)   # Root read/write only — config may contain VPN endpoints
            os.replace(tmp_path, str(dest))
        except Exception as e:
            logger.error("Failed to save config to %s: %s", path, e)

