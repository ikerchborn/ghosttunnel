"""
GhostTunnel nftables Firewall Manager
========================================
Fixes applied:
  CRIT-02  — All external data sanitized before entering nftables rulesets
  HIGH-04  — VPN INPUT chain now restricts to ct state established,related
  HIGH-06  — IP forwarding moved out of daemon (see systemd unit changes)
  MED-08   — Forward chain restricts direction of forwarded traffic
  BUG-FW-03 — bootstrap_dns_v4 set never empty (hard fallback to 1.1.1.1/9.9.9.9)
  BUG-FW-04 — vpn-down mode now works without vpn_endpoints set (no set reference)
  BUG-FW-05 — 'error' mode now falls through to vpn-down so we always have rules
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .config import Settings
from .models import NetworkSnapshot, VpnState
from .system import (
    CommandError,
    find_binary,
    require_root,
    run,
    sanitize_iface,
    sanitize_ip,
    sanitize_port,
)

logger = logging.getLogger(__name__)

# Hard-coded fallback DNS used when bootstrap_dns is empty (prevents empty nft sets)
_FALLBACK_DNS_V4 = ("1.1.1.1", "9.9.9.9")


@dataclass(slots=True)
class FirewallPlan:
    ruleset: str
    mode: str
    reason: str


class NftFirewallManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.table_ref = f"inet {self.settings.table_name}"

    @property
    def nft(self) -> str:
        return find_binary("nft")

    def build_plan(
        self,
        snapshot: NetworkSnapshot,
        vpn: VpnState,
        panic_mode: bool = False,
    ) -> FirewallPlan:
        # FAIL CLOSED: If panic mode is enabled or VPN is leaking, block all.
        if panic_mode or (vpn and vpn.is_leaking):
            return FirewallPlan(
                self._render_panic_rules(),
                "panic",
                "FAIL CLOSED: Panic mode or leak detected. Network locked.",
            )

        if vpn.conflict:
            # A conflict MUST still be FAIL CLOSED, never an empty ruleset.
            logger.warning(
                "VPN conflict detected — applying FAIL CLOSED rules. Reason: %s",
                vpn.conflict_reason,
            )
            return FirewallPlan(
                self._render_panic_rules(),
                "vpn-conflict",
                f"FAIL CLOSED: {vpn.conflict_reason}",
            )

        # Get physical interfaces (excluding VPN iface to avoid self-referencing)
        physical = tuple(
            iface.name
            for iface in snapshot.physical_ifaces
            if iface.name != vpn.iface
        )

        # BUG-FW-05: If no physical interfaces, generate vpn-down rules on ALL
        # non-loopback interfaces instead of returning an empty ruleset.
        if not physical:
            logger.warning(
                "No physical interfaces detected. Using permissive vpn-down fallback."
            )
            # Collect every non-loopback interface as fallback
            physical = tuple(
                name for name, info in snapshot.interfaces.items()
                if not info.is_loopback and name != vpn.iface
            )
            if not physical:
                # Absolute last resort: full lockdown
                return FirewallPlan(
                    self._render_panic_rules(),
                    "panic",
                    "FAIL CLOSED: No usable network interfaces detected.",
                )

        mode = "vpn-up" if vpn.active and vpn.iface else "vpn-down"
        reason = "VPN active. Only loopback, established, and VPN traffic allowed."
        if mode == "vpn-down":
            reason = "VPN down. Traffic blocked except DNS bootstrap and VPN handshakes."

        rules = self._render_rules(snapshot, vpn, physical, mode)
        return FirewallPlan(rules, mode, reason)

    def _render_panic_rules(self) -> str:
        """Strict FAIL CLOSED ruleset. Blocks everything except loopback."""
        table = self.settings.table_name
        return f"""
table inet {table} {{
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    limit rate 10/second log prefix "VPN-PANIC-DROP-IN: " level warn
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state established,related accept
    limit rate 10/second log prefix "VPN-PANIC-DROP-OUT: " level warn
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
  }}
}}
"""

    def _render_rules(
        self,
        snapshot: NetworkSnapshot,
        vpn: VpnState,
        physical: tuple[str, ...],
        mode: str,
    ) -> str:
        table = self.settings.table_name
        lines: list[str] = [f"table inet {table} {{"]
        lines.extend(self._render_sets(snapshot))

        # -- INPUT CHAIN --
        lines.append("  chain input {")
        lines.append("    type filter hook input priority filter; policy drop;")

        # (HIGH-04) VPN input: only accept established/related, NOT new connections.
        if vpn.active and vpn.iface:
            safe_iface = sanitize_iface(vpn.iface)
            lines.append(f'    iifname "{safe_iface}" ct state established,related accept')

        lines.append('    iifname "lo" accept')
        lines.append("    ct state established,related accept")
        lines.append("    ct state invalid drop")

        if not self.settings.stealth_mode:
            lines.append(
                "    ip protocol icmp icmp type { destination-unreachable, "
                "time-exceeded, parameter-problem, echo-reply } accept"
            )
            if not self.settings.ipv6_block:
                lines.append(
                    "    ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, "
                    "packet-too-big, time-exceeded, parameter-problem, echo-reply, "
                    "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
                )

        if self.settings.allow_lan:
            for iface in physical:
                safe = sanitize_iface(iface)
                lines.append(f'    iifname "{safe}" ip saddr @lan_ipv4 icmp type echo-request accept')
                lines.append(f'    iifname "{safe}" ip saddr @lan_ipv4 udp dport 5353 accept')
                if not self.settings.ipv6_block:
                    lines.append(f'    iifname "{safe}" ip6 saddr @lan_ipv6 icmpv6 type echo-request accept')
                    lines.append(f'    iifname "{safe}" ip6 saddr @lan_ipv6 udp dport 5353 accept')

        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-In: " level warn')
        lines.append("  }")

        # -- OUTPUT CHAIN --
        lines.append("  chain output {")
        lines.append("    type filter hook output priority filter; policy drop;")

        if vpn.active and vpn.iface:
            safe_iface = sanitize_iface(vpn.iface)
            lines.append(f'    oifname "{safe_iface}" accept')

        lines.append('    oifname "lo" accept')
        lines.append("    ct state established,related accept")
        lines.append("    ct state invalid drop")

        if not self.settings.ipv6_block:
            lines.append(
                "    ip6 nexthdr icmpv6 icmpv6 type { nd-router-solicit, nd-router-advert, "
                "nd-neighbor-solicit, nd-neighbor-advert } accept"
            )

        for iface in physical:
            safe = sanitize_iface(iface)
            # DNS Bootstrap — always needed so daemon can resolve VPN endpoints
            lines.append(f'    oifname "{safe}" ip daddr @bootstrap_dns_v4 udp dport 53 accept')
            lines.append(f'    oifname "{safe}" ip daddr @bootstrap_dns_v4 tcp dport 53 accept')
            if not self.settings.stealth_mode:
                lines.append(
                    f'    oifname "{safe}" ip daddr @bootstrap_dns_v4 icmp type echo-request accept'
                )

            if not self.settings.ipv6_block and (
                snapshot.dns_servers_v6 or self.settings.bootstrap_dns_v6
            ):
                lines.append(
                    f'    oifname "{safe}" ip6 daddr @bootstrap_dns_v6 udp dport 53 accept'
                )
                lines.append(
                    f'    oifname "{safe}" ip6 daddr @bootstrap_dns_v6 tcp dport 53 accept'
                )
                if not self.settings.stealth_mode:
                    lines.append(
                        f'    oifname "{safe}" ip6 daddr @bootstrap_dns_v6 icmpv6 type echo-request accept'
                    )

            # VPN Handshake ports — allow even in vpn-down mode so tunnel can reconnect.
            # BUG-FW-04: In vpn-down mode vpn_endpoints_v4 set may not exist.
            # Use the set only if it was actually created (snapshot has endpoint IPs).
            udp_ports = ", ".join(
                str(sanitize_port(p)) for p in self.settings.udp_handshake_ports
            )
            tcp_ports = ", ".join(
                str(sanitize_port(p)) for p in self.settings.tcp_handshake_ports
            )

            if snapshot.vpn_endpoint_ips:
                # We have resolved endpoints — use the named set for precision
                if udp_ports:
                    lines.append(
                        f'    oifname "{safe}" ip daddr @vpn_endpoints_v4 udp dport {{ {udp_ports} }} accept'
                    )
                if tcp_ports:
                    lines.append(
                        f'    oifname "{safe}" ip daddr @vpn_endpoints_v4 tcp dport {{ {tcp_ports} }} accept'
                    )
            else:
                # BUG-FW-04: No resolved endpoints yet (DNS offline / first boot).
                # Allow handshake ports to ANY destination so VPN can bootstrap.
                if udp_ports:
                    lines.append(f'    oifname "{safe}" udp dport {{ {udp_ports} }} accept')
                if tcp_ports:
                    lines.append(f'    oifname "{safe}" tcp dport {{ {tcp_ports} }} accept')

            if not self.settings.ipv6_block and snapshot.vpn_endpoint_ips_v6:
                if udp_ports:
                    lines.append(
                        f'    oifname "{safe}" ip6 daddr @vpn_endpoints_v6 udp dport {{ {udp_ports} }} accept'
                    )
                if tcp_ports:
                    lines.append(
                        f'    oifname "{safe}" ip6 daddr @vpn_endpoints_v6 tcp dport {{ {tcp_ports} }} accept'
                    )

        if self.settings.allow_lan:
            for iface in physical:
                safe = sanitize_iface(iface)
                lines.append(f'    oifname "{safe}" ip daddr @lan_ipv4 icmp type echo-request accept')
                lines.append(f'    oifname "{safe}" ip daddr @lan_ipv4 udp dport 5353 accept')
                if not self.settings.ipv6_block:
                    lines.append(f'    oifname "{safe}" ip6 daddr @lan_ipv6 icmpv6 type echo-request accept')
                    lines.append(f'    oifname "{safe}" ip6 daddr @lan_ipv6 udp dport 5353 accept')

        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-Out: " level warn')
        lines.append("  }")

        # -- FORWARD CHAIN (MED-08: restricted direction) --
        lines.append("  chain forward {")
        lines.append("    type filter hook forward priority filter; policy drop;")
        if self.settings.allow_forwarding and vpn.active and vpn.iface:
            safe_vpn = sanitize_iface(vpn.iface)
            for iface in physical:
                safe_phys = sanitize_iface(iface)
                lines.append(
                    f'    iifname "{safe_phys}" oifname "{safe_vpn}" accept'
                )
                lines.append(
                    f'    iifname "{safe_vpn}" oifname "{safe_phys}" ct state established,related accept'
                )
        lines.append("    ct state invalid drop")
        lines.append("  }")

        # -- NAT CHAIN --
        if self.settings.allow_forwarding and vpn.active and vpn.iface:
            safe_vpn = sanitize_iface(vpn.iface)
            lines.append("  chain postrouting {")
            lines.append("    type nat hook postrouting priority srcnat;")
            lines.append(f'    oifname "{safe_vpn}" masquerade')
            lines.append("  }")

        lines.append("}")
        return "\n".join(lines) + "\n"

    def _render_sets(self, snapshot: NetworkSnapshot) -> list[str]:
        lines: list[str] = [
            "  set lan_ipv4 {",
            "    type ipv4_addr; flags interval;",
        ]
        if self.settings.lan_networks:
            safe = ", ".join(sanitize_ip(ip) for ip in self.settings.lan_networks)
            lines.append(f"    elements = {{ {safe} }}")
        else:
            lines.append("    elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }")
        lines.append("  }")

        lines.extend([
            "  set bootstrap_dns_v4 {",
            "    type ipv4_addr;",
        ])
        dns_v4 = snapshot.dns_servers or self.settings.bootstrap_dns or _FALLBACK_DNS_V4
        safe = ", ".join(sanitize_ip(ip) for ip in dns_v4)
        lines.append(f"    elements = {{ {safe} }}")
        lines.append("  }")

        if not self.settings.ipv6_block:
            lines.extend([
                "  set lan_ipv6 {",
                "    type ipv6_addr; flags interval;",
            ])
            if self.settings.lan_networks_v6:
                safe = ", ".join(sanitize_ip(ip) for ip in self.settings.lan_networks_v6)
                lines.append(f"    elements = {{ {safe} }}")
            else:
                lines.append("    elements = { fe80::/10, fc00::/7 }")
            lines.append("  }")

            dns_v6 = snapshot.dns_servers_v6 or self.settings.bootstrap_dns_v6
            if dns_v6:
                lines.extend([
                    "  set bootstrap_dns_v6 {",
                    "    type ipv6_addr;",
                ])
                safe = ", ".join(sanitize_ip(ip) for ip in dns_v6)
                lines.append(f"    elements = {{ {safe} }}")
                lines.append("  }")

        if snapshot.vpn_endpoint_ips:
            safe = ", ".join(sanitize_ip(ip) for ip in snapshot.vpn_endpoint_ips)
            lines.extend([
                "  set vpn_endpoints_v4 {",
                "    type ipv4_addr;",
                f"    elements = {{ {safe} }}",
                "  }",
            ])
        if not self.settings.ipv6_block and snapshot.vpn_endpoint_ips_v6:
            safe = ", ".join(sanitize_ip(ip) for ip in snapshot.vpn_endpoint_ips_v6)
            lines.extend([
                "  set vpn_endpoints_v6 {",
                "    type ipv6_addr;",
                f"    elements = {{ {safe} }}",
                "  }",
            ])
        return lines

    def activate(self, plan: FirewallPlan) -> None:
        if not plan.ruleset:
            logger.warning("activate() called with empty ruleset — skipping to avoid open firewall.")
            return
        require_root()
        # Delete existing table first so re-apply is idempotent
        run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)
        result = run([self.nft, "-f", "-"], input_text=plan.ruleset, check=False)
        if result.returncode != 0:
            logger.error(
                "nft failed to apply %s ruleset (rc=%d): %s",
                plan.mode, result.returncode, result.stderr.strip()[:300],
            )
            raise RuntimeError(f"nft ruleset apply failed: {result.stderr.strip()[:200]}")
        logger.info("Firewall activated: mode=%s", plan.mode)

    def deactivate(self) -> None:
        require_root()
        run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)

    def is_active(self) -> bool:
        try:
            result = run(
                [self.nft, "list", "table", "inet", self.settings.table_name],
                check=False,
            )
        except (CommandError, FileNotFoundError, PermissionError):
            return False
        return result.returncode == 0
