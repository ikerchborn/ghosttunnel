"""
GhostTunnel Data Models
=========================
Fixes applied:
  MED-05 — is_up no longer treats UNKNOWN as UP
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(slots=True)
class InterfaceInfo:
    name: str
    flags: tuple[str, ...] = ()
    state: str = "UNKNOWN"
    link_type: str = ""
    mac: str = ""
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    is_loopback: bool = False
    is_virtual: bool = False

    @property
    def is_up(self) -> bool:
        """
        (MED-05) Only 'UP' is treated as definitively up.
        'UNKNOWN' is common for loopback / virtual interfaces and should
        NOT be trusted as a positive VPN detection signal.
        """
        return self.state.upper() == "UP"

    @property
    def is_physical(self) -> bool:
        return not self.is_loopback and not self.is_virtual


@dataclass(slots=True)
class NetworkSnapshot:
    interfaces: dict[str, InterfaceInfo] = field(default_factory=dict)
    default_route_iface: str | None = None
    route_probe_iface: str | None = None
    dns_servers: tuple[str, ...] = ()
    dns_servers_v6: tuple[str, ...] = ()
    vpn_endpoint_ips: tuple[str, ...] = ()
    vpn_endpoint_ips_v6: tuple[str, ...] = ()

    @property
    def physical_ifaces(self) -> tuple[InterfaceInfo, ...]:
        return tuple(i for i in self.interfaces.values() if i.is_physical)


@dataclass(slots=True)
class VpnState:
    active: bool
    iface: str | None = None
    provider: str = "unknown"
    verified_by_route: bool = False
    proton_native_killswitch: bool = False
    conflict: bool = False
    conflict_reason: str = ""
    is_leaking: bool = False  # Track if a leak was detected


@dataclass(slots=True)
class ControllerState:
    mode: str
    firewall_active: bool
    reason: str
    physical_ifaces: tuple[str, ...]
    vpn_iface: str | None
    vpn_provider: str
    route_probe_iface: str | None
    dns_servers: tuple[str, ...]
    dns_servers_v6: tuple[str, ...]
    proton_native_killswitch: bool
    panic_mode: bool = False
