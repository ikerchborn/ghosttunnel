from __future__ import annotations
import json
import logging
from pathlib import Path

from .config import Settings
from .models import InterfaceInfo, NetworkSnapshot
from .system import run, find_binary
from .dns_protection import resolve_hosts, get_dns_servers

logger = logging.getLogger(__name__)

class LeakDetector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.ip_bin = find_binary("ip")

    def snapshot(self) -> NetworkSnapshot:
        interfaces = self._load_interfaces()
        dns_v4, dns_v6 = get_dns_servers(self.settings)
        vpn_v4, vpn_v6 = resolve_hosts(self.settings.custom_vpn_endpoints)
        
        return NetworkSnapshot(
            interfaces=interfaces,
            default_route_iface=self._default_route_iface(),
            route_probe_iface=self._probe_route_iface(),
            dns_servers=dns_v4,
            dns_servers_v6=dns_v6,
            vpn_endpoint_ips=vpn_v4,
            vpn_endpoint_ips_v6=vpn_v6,
        )

    def is_leaking(self, snapshot: NetworkSnapshot, active_vpn_iface: str | None) -> bool:
        """
        Check for conditions that indicate a leak is occurring.
        If a leak is detected, FAIL CLOSED panic mode should be engaged.
        """
        if not active_vpn_iface:
            return False # No VPN expected, no leak.

        # 1. Routing Leak: Default route goes through physical interface instead of VPN
        default_iface = snapshot.default_route_iface
        if default_iface and default_iface != active_vpn_iface:
            logger.warning(
                "ROUTING LEAK: Default route is on %s, expected %s",
                default_iface, active_vpn_iface,
            )
            return True
            
        # 2. IPv6 Leak: VPN interface does not have IPv6, but physical does, and IPv6 is not blocked.
        if not self.settings.ipv6_block:
            vpn_info = snapshot.interfaces.get(active_vpn_iface)
            if vpn_info and not vpn_info.ipv6:
                for iface in snapshot.physical_ifaces:
                    if iface.ipv6:
                        logger.warning(
                            "IPv6 LEAK: Physical iface %s has IPv6 but VPN iface %s doesn't.",
                            iface.name, active_vpn_iface,
                        )
                        return True

        # WebRTC leaks are natively mitigated by the nftables DROP policy, 
        # as the UDP packets for STUN/TURN cannot exit the physical interface.
        return False

    def _load_interfaces(self) -> dict[str, InterfaceInfo]:
        link_data = json.loads(run([self.ip_bin, "-json", "link", "show"]).stdout or "[]")
        addr_data = json.loads(run([self.ip_bin, "-json", "addr", "show"]).stdout or "[]")
        addr_map = {
            entry.get("ifname", ""): entry.get("addr_info", [])
            for entry in addr_data if entry.get("ifname")
        }
        
        interfaces: dict[str, InterfaceInfo] = {}
        for entry in link_data:
            name = entry.get("ifname", "")
            if not name: continue
            
            info = InterfaceInfo(
                name=name,
                flags=tuple(entry.get("flags", [])),
                state=entry.get("operstate", "UNKNOWN"),
                link_type=entry.get("link_type", ""),
                mac=entry.get("address", ""),
                is_loopback=name == "lo" or entry.get("link_type") == "loopback",
                is_virtual=self._is_virtual(name),
                ipv4=tuple(
                    item["local"] for item in addr_map.get(name, [])
                    if item.get("family") == "inet" and item.get("local")
                ),
                ipv6=tuple(
                    item["local"] for item in addr_map.get(name, [])
                    if item.get("family") == "inet6" and item.get("local")
                ),
            )
            interfaces[name] = info
        return interfaces

    def _is_virtual(self, iface: str) -> bool:
        if iface == "lo": return True
        return not Path(f"/sys/class/net/{iface}/device").exists()

    def _default_route_iface(self) -> str | None:
        output = run([self.ip_bin, "-json", "route", "show", "default"], check=False).stdout
        try:
            routes = json.loads(output or "[]")
        except json.JSONDecodeError:
            routes = []
        # BUG-LEAK-02: Pick the lowest-metric route to avoid ECMP false positives.
        best = None
        best_metric = float("inf")
        for route in routes:
            iface = route.get("dev")
            if not iface:
                continue
            metric = route.get("metric", 0)
            if metric < best_metric:
                best_metric = metric
                best = iface
        return best

    def _probe_route_iface(self) -> str | None:
        result = run([self.ip_bin, "route", "get", "1.1.1.1"], check=False).stdout.strip()
        parts = result.split()
        if "dev" in parts:
            idx = parts.index("dev") + 1
            if idx < len(parts):
                return parts[idx]
        return None
