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
            if not (name.startswith("wg") or name.startswith("mullvad") or name.startswith("nordlynx")):
                continue

            # (MED-05) WireGuard interfaces report UNKNOWN operstate by design.
            # An interface is active if it's UP *or* has at least one IP
            # assigned (wg-quick sets the IP when it brings the tunnel up).
            is_active = info.is_up or bool(info.ipv4)
            if not is_active:
                continue

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
