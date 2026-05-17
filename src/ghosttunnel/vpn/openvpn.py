"""
OpenVPN Adapter
=================
Fixes applied:
  MED-01 — Logs a warning if the tun/tap interface isn't the default route
  MED-05 — Also accepts interfaces that have an IP assigned (split-tunnel support)
"""
import logging
from .generic import VpnAdapter
from ghosttunnel.core.models import VpnState, NetworkSnapshot

logger = logging.getLogger(__name__)


class OpenVpnAdapter(VpnAdapter):
    def __init__(self):
        super().__init__("openvpn")

    def get_state(self, snapshot: NetworkSnapshot) -> VpnState:
        for name, info in snapshot.interfaces.items():
            if not (name.startswith("tun") or name.startswith("tap")):
                continue

            # (MED-05) Accept interface if UP *or* has an IP assigned.
            is_active = info.is_up or bool(info.ipv4)
            if not is_active:
                continue

            # (MED-01) Warn if not on the default route.
            if (snapshot.default_route_iface
                    and snapshot.default_route_iface != name):
                logger.warning(
                    "OpenVPN iface %s detected but default route is via %s. "
                    "Possible split-tunnel or routing misconfiguration.",
                    name, snapshot.default_route_iface,
                )

            return VpnState(active=True, iface=name, provider=self.name)

        return VpnState(active=False, provider=self.name)

    def reconnect(self) -> bool:
        logger.warning(
            "OpenVPN auto-reconnect requires 'systemctl restart openvpn@<config>'. "
            "Not fully implemented — manual intervention required."
        )
        return False
