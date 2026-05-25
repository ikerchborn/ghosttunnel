"""
WireGuard VPN Adapter
=======================
Fixes applied:
  MED-01  — Logs a warning if WireGuard interface isn't on the default route
  MED-05  — Detection no longer relies on operstate='UP' alone;
            WireGuard interfaces legitimately report UNKNOWN operstate,
            so we also accept interfaces that have an IP address assigned
            (proof that wg-quick has configured the tunnel).
"""
import logging
from .generic import VpnAdapter
from ghosttunnel.core.models import VpnState, NetworkSnapshot

logger = logging.getLogger(__name__)


class WireguardAdapter(VpnAdapter):
    def __init__(self):
        super().__init__("wireguard")

    def get_state(self, snapshot: NetworkSnapshot) -> VpnState:
        for name, info in snapshot.interfaces.items():
            # Mullvad: wg0-mullvad, wg1-mullvad (suffix), or mullvad-XXXX (prefix)
            # NordVPN: nordlynx (WG), nordtun (OpenVPN legacy)
            if not (
                name.startswith("wg")
                or name.startswith("mullvad")
                or name.endswith("-mullvad")
                or name.startswith("nordlynx")
                or name.startswith("nordtun")
            ):
                continue

            # (MED-05) WireGuard interfaces report UNKNOWN operstate by design.
            # An interface is active if it's UP *or* has at least one IP
            # assigned (wg-quick sets the IP when it brings the tunnel up).
            is_active = info.is_up or bool(info.ipv4)
            if not is_active:
                continue

            # (NEW) Validate handshake via wg show
            try:
                from ghosttunnel.core.system import run, find_binary
                wg_bin = find_binary("wg")
                res = run([wg_bin, "show", name, "latest-handshakes"], check=False)
                if res.returncode == 0 and res.stdout.strip():
                    # Output format: <peer_pubkey> \t <timestamp>
                    handshakes = res.stdout.strip().split("\n")
                    active_peers = 0
                    for line in handshakes:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1] != "0":
                            active_peers += 1
                    if active_peers == 0:
                        logger.warning("WireGuard interface %s exists but has 0 active handshakes.", name)
                        # We still consider it 'active' to avoid looping between UP and DOWN 
                        # just because the tunnel is idle, but we log the warning for auditing.
                        # (A full implementation could track handshake age).
            except Exception as e:
                logger.debug("Failed to check wg show for %s: %s", name, e)

            # (MED-01) Warn if this interface isn't carrying the default route.
            if (snapshot.default_route_iface
                    and snapshot.default_route_iface != name):
                logger.warning(
                    "WireGuard iface %s detected but default route is via %s. "
                    "Possible split-tunnel or routing misconfiguration.",
                    name, snapshot.default_route_iface,
                )

            return VpnState(active=True, iface=name, provider=self.name)

        return VpnState(active=False, provider=self.name)

    def reconnect(self) -> bool:
        logger.warning(
            "WireGuard auto-reconnect requires wg-quick or a config manager. "
            "Manual intervention may be needed."
        )
        return False
