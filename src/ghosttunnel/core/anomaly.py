from __future__ import annotations
import logging
from ghosttunnel.core.models import NetworkSnapshot

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Passive anomaly detector for monitoring unexpected network routing or interface states.
    """

    def __init__(self) -> None:
        """
        Initialize the anomaly detector with an empty list of past anomalies.
        """
        self.last_anomalies: list[str] = []

    def analyze(
        self,
        snapshot: NetworkSnapshot,
        current_mode: str,
        vpn_provider: str,
        vpn_iface: str,
    ) -> list[str]:
        """
        Passively analyzes the network snapshot for anomalous behavior.

        Args:
            snapshot: The current network snapshot.
            current_mode: The active operation mode (e.g. 'vpn-up', 'panic').
            vpn_provider: Name of the current active VPN provider.
            vpn_iface: Name of the expected VPN interface.

        Returns:
            A list of detected anomaly descriptions.
        """
        anomalies: list[str] = []

        if current_mode == "vpn-up":
            # Anomaly 1: Traffic routing mismatch
            if snapshot.default_route_iface:
                # The default gateway interface should be the VPN iface, or routing should be handled via fwmark.
                # If we detect the default route is purely on a physical interface with no VPN encapsulation, flag it.
                gw_iface = snapshot.default_route_iface
                if gw_iface and gw_iface != vpn_iface and not gw_iface.startswith("pvpn"):
                    # This might be normal for policy routing, but we flag it for OPSEC visibility
                    anomalies.append(f"Routing anomaly: Default route is on {gw_iface}, expected {vpn_iface}.")

            # Anomaly 2: Missing VPN interface
            # If we are in 'vpn-up' mode but the interface does not exist in the OS anymore
            if vpn_iface and vpn_iface not in snapshot.interfaces:
                anomalies.append(f"Interface anomaly: {vpn_iface} vanished while VPN state is UP.")

        elif current_mode == "panic":
            # Anomaly 3: Default gateway exists during panic
            if snapshot.default_route_iface:
                gw_iface = snapshot.default_route_iface
                anomalies.append(f"Panic anomaly: A default route exists on {gw_iface} while in PANIC mode.")

        # Deduplicate and update
        new_anomalies = list(set(anomalies))
        self.last_anomalies = new_anomalies
        return new_anomalies

