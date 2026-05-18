"""
Custom VPN Adapter
====================
Detects custom VPN interfaces based on the `vpn_hints` configuration list.
This ensures that user-defined interfaces in /etc/ghosttunnel/config.json
are properly evaluated by the daemon.
"""
import logging
from .generic import VpnAdapter
from ghosttunnel.core.models import VpnState, NetworkSnapshot
from ghosttunnel.core.config import Settings

logger = logging.getLogger(__name__)


class CustomVpnAdapter(VpnAdapter):
    def __init__(self, settings: Settings):
        super().__init__("custom")
        self.settings = settings

    def get_state(self, snapshot: NetworkSnapshot) -> VpnState:
        # If no custom hints exist, nothing to do
        if not self.settings.vpn_hints:
            return VpnState(active=False, provider=self.name)

        for name, info in snapshot.interfaces.items():
            # Check if interface matches any hint provided by user
            is_match = any(name.startswith(hint) for hint in self.settings.vpn_hints)
            if not is_match:
                continue

            # Consider active if UP or has an IP assigned
            is_active = info.is_up or bool(info.ipv4)
            if not is_active:
                continue

            if (snapshot.default_route_iface
                    and snapshot.default_route_iface != name):
                logger.warning(
                    "Custom VPN iface %s detected but default route is via %s. "
                    "Possible split-tunnel or routing misconfiguration.",
                    name, snapshot.default_route_iface,
                )

            return VpnState(active=True, iface=name, provider=self.name)

        return VpnState(active=False, provider=self.name)

    def reconnect(self) -> bool:
        logger.warning("Auto-reconnect is not supported for custom VPN interfaces.")
        return False
