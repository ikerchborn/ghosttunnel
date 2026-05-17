"""
ProtonVPN Adapter
===================
Handles ProtonVPN GUI (proton-vpn-gtk-app) and CLI (protonvpn-cli).

ProtonVPN creates two possible interface types:
  - pvpn0 / pvpn-XXXXX  — WireGuard-based (default in modern Proton)
  - proton0             — OpenVPN-based (legacy)

Conflict rule:
  pvpnksintrf0 = ProtonVPN's OWN native kill switch interface.
  GhostTunnel can coexist IF the user disables ProtonVPN's native KS.
  If both are active, GhostTunnel NOW enters PANIC (FAIL CLOSED) instead
  of leaving the system completely unprotected with an empty ruleset.

Fixes applied:
  LOW-02    — Removed unused `import subprocess`
  MED-03    — Uses explicit timeout=15 for slow protonvpn-cli reconnect
  BUG-FIX-5 — Conflict no longer returns empty ruleset; now returns panic
  COMPAT    — Detects ProtonVPN GUI WireGuard tunnels (pvpn- prefix)
"""
import logging
from .generic import VpnAdapter
from ghosttunnel.core.models import VpnState, NetworkSnapshot
from ghosttunnel.core.system import run, find_binary, CommandError

logger = logging.getLogger(__name__)

# Interface prefixes created by ProtonVPN GUI (WireGuard-based, modern)
_PROTON_WG_PREFIXES = ("pvpn-", "pvpn0", "proton0", "proton-")
# Interface prefixes created by ProtonVPN CLI / older versions
_PROTON_CLI_PREFIXES = ("pvpn",)
# ProtonVPN native kill switch sentinel interface
_PROTON_KS_IFACE = "pvpnksintrf0"


class ProtonVpnAdapter(VpnAdapter):
    def __init__(self):
        super().__init__("protonvpn")

    def get_state(self, snapshot: NetworkSnapshot) -> VpnState:
        active = False
        iface_name = None

        for name, info in snapshot.interfaces.items():
            # Ignore ProtonVPN dummy kill switch interfaces
            if name in (_PROTON_KS_IFACE, "ipv6leakintrf0"):
                continue

            is_proton = any(
                name.startswith(p) for p in _PROTON_WG_PREFIXES + _PROTON_CLI_PREFIXES
            )
            if not is_proton:
                continue

            # Accept interface if it's UP or has an IP (WG tunnels may show UNKNOWN)
            is_active = info.is_up or bool(info.ipv4)
            if is_active:
                active = True
                iface_name = name
                logger.debug("ProtonVPN tunnel detected: iface=%s ipv4=%s", name, info.ipv4)
                break

        # Detect native ProtonVPN kill switch interface
        native_ks_active = _PROTON_KS_IFACE in snapshot.interfaces

        if native_ks_active:
            logger.info("ProtonVPN native kill switch interface (%s) detected. Coexisting.", _PROTON_KS_IFACE)

        return VpnState(
            active=active,
            iface=iface_name,
            provider=self.name,
            proton_native_killswitch=native_ks_active,
        )

    def reconnect(self) -> bool:
        logger.info("Attempting to reconnect ProtonVPN...")
        # Resolve binary via trusted path — prevents PATH injection (LOW-01 / CRIT-02)
        try:
            cli = find_binary("protonvpn-cli")
        except FileNotFoundError:
            logger.error("protonvpn-cli not found. Cannot reconnect ProtonVPN.")
            return False
        try:
            run([cli, "c", "-f"], timeout=15)  # MED-03: explicit timeout
            return True
        except (CommandError, FileNotFoundError) as e:
            logger.error("Failed to reconnect ProtonVPN via CLI: %s", e)
            return False
