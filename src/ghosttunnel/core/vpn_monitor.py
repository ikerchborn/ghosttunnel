"""
GhostTunnel VPN Monitor
=========================
Fixes applied:
  MED-01 — Logs routing discrepancies to aid in false-positive debugging
"""
from __future__ import annotations
import logging

from .models import NetworkSnapshot, VpnState
from ghosttunnel.vpn import get_adapters

logger = logging.getLogger(__name__)


class VpnMonitor:
    def __init__(self):
        self.adapters = get_adapters()

    def determine_state(self, snapshot: NetworkSnapshot) -> VpnState:
        """
        Iterates over VPN adapters in priority order to determine the
        current active VPN state. Returns first active VPN found, or a
        down state if none are active.
        """
        for adapter in self.adapters:
            state = adapter.get_state(snapshot)

            # Conflict takes priority over everything else
            if state.conflict:
                logger.warning(
                    "VPN conflict detected by %s: %s",
                    adapter.name, state.conflict_reason,
                )
                return state

            if state.active and state.iface:
                logger.debug(
                    "VPN active: provider=%s iface=%s default_route=%s",
                    state.provider, state.iface, snapshot.default_route_iface,
                )
                return state

        # No VPN is active
        return VpnState(active=False)
