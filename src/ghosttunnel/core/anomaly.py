import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.last_anomalies = []

    def analyze(self, snapshot, current_mode: str, vpn_provider: str, vpn_iface: str) -> list[str]:
        """
        Passively analyzes the network snapshot for anomalous behavior.
        Returns a list of alert strings if anomalies are found.
        """
        anomalies = []

        if current_mode == "vpn-up":
            # Anomaly 1: Traffic routing mismatch
            if snapshot.default_gateway:
                # The default gateway interface should be the VPN iface, or routing should be handled via fwmark.
                # If we detect the default route is purely on a physical interface with no VPN encapsulation, flag it.
                gw_iface = snapshot.default_gateway.get("dev", "")
                if gw_iface and gw_iface != vpn_iface and not gw_iface.startswith("pvpn"):
                    # This might be normal for policy routing, but we flag it for OPSEC visibility
                    anomalies.append(f"Routing anomaly: Default route is on {gw_iface}, expected {vpn_iface}.")

            # Anomaly 2: Missing VPN interface
            # If we are in 'vpn-up' mode but the interface does not exist in the OS anymore
            if vpn_iface and not any(vpn_iface in list(link.keys())[0] for link in snapshot.links if link):
                anomalies.append(f"Interface anomaly: {vpn_iface} vanished while VPN state is UP.")

        elif current_mode == "panic":
            # Anomaly 3: Default gateway exists during panic
            if snapshot.default_gateway:
                gw_iface = snapshot.default_gateway.get("dev", "")
                anomalies.append(f"Panic anomaly: A default route exists on {gw_iface} while in PANIC mode.")

        # Deduplicate and update
        new_anomalies = list(set(anomalies))
        self.last_anomalies = new_anomalies
        return new_anomalies
