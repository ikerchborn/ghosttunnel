"""
GhostTunnel Daemon
====================
Fixes applied:
  CRIT-01 — Pre-boot panic rules applied before first poll cycle
  CRIT-04 — IPC server integrated (panic, panic-disable, status via socket)
  HIGH-01 — Status file permissions restricted to 0o640
  MED-07  — Exception messages sanitized before persisting to status file
  LOW-04  — Daemon writes a PID file for reliable process tracking
"""
import json
import logging
import os
import signal
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from ghosttunnel.core.config import Settings
from ghosttunnel.core.models import ControllerState
from ghosttunnel.core.firewall import NftFirewallManager, FirewallPlan
from ghosttunnel.core.leak_detector import LeakDetector
from ghosttunnel.core.vpn_monitor import VpnMonitor
from ghosttunnel.core.vpn_rotator import VpnRotator
from ghosttunnel.core.emergency import EmergencyController
from ghosttunnel.core.ipc import IpcServer

logger = logging.getLogger(__name__)

# Maximum length of exception text persisted to status/logs (MED-07)
_MAX_ERROR_MSG = 200


def _sanitize_error(exc: Exception) -> str:
    """Strip paths and limit length of error messages exposed in status file."""
    raw = str(exc)
    # Remove file system paths that could leak internal structure
    sanitized = raw.split("/")[-1] if "/" in raw else raw
    return sanitized[:_MAX_ERROR_MSG]


class GhostDaemon:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.leak_detector = LeakDetector(settings)
        self.vpn_monitor = VpnMonitor()
        self.vpn_rotator = VpnRotator(settings)
        self.firewall = NftFirewallManager(settings)
        self.emergency = EmergencyController()

        self._running = False
        self._last_signature = None
        self._ipc: IpcServer | None = None
        self._last_state: ControllerState | None = None

    # ------------------------------------------------------------------
    # CRIT-01 — Apply blocking rules immediately before entering the loop
    # ------------------------------------------------------------------
    def _apply_boot_rules(self) -> None:
        """
        Ensure the network is locked BEFORE the first snapshot completes.
        If the daemon starts with an existing panic lock, apply panic rules.
        Otherwise apply a strict 'vpn-down' policy that only permits DNS +
        VPN handshake traffic.
        """
        try:
            if self.emergency.is_panic():
                logger.warning("Panic lock found at boot — applying FAIL CLOSED rules immediately.")
                plan = FirewallPlan(
                    self.firewall._render_panic_rules(),
                    "panic",
                    "FAIL CLOSED: Panic state persisted from previous run.",
                )
            else:
                # Boot-safe: block everything except DNS bootstrap + VPN handshake
                plan = FirewallPlan(
                    self.firewall._render_panic_rules(),
                    "boot",
                    "Boot lockdown: blocking until first successful sync.",
                )
            self.firewall.activate(plan)
            logger.info("Boot rules applied: mode=%s", plan.mode)
        except Exception as exc:
            logger.error("Failed to apply boot rules: %s", exc)

    def sync(self) -> ControllerState:
        try:
            snapshot = self.leak_detector.snapshot()
            vpn_state = self.vpn_monitor.determine_state(snapshot)

            # Leak Check
            if self.leak_detector.is_leaking(snapshot, vpn_state.iface):
                vpn_state.is_leaking = True
                self.emergency.trigger_panic("Network leak detected")

            # VPN Rotation Logic
            if not vpn_state.active and not self.emergency.is_panic():
                logger.warning("VPN is down. Evaluating rotation...")
                if self.vpn_rotator.rotate(vpn_state.provider):
                    logger.info("Rotation triggered. Waiting for interface...")
                else:
                    if self.settings.auto_rotate:
                        self.emergency.trigger_panic("All VPN rotation attempts failed")

            if vpn_state.active and not vpn_state.is_leaking:
                self.vpn_rotator.reset()

            # Firewall Planning
            plan = self.firewall.build_plan(snapshot, vpn_state, self.emergency.is_panic())

            # State Signature check
            signature = json.dumps({
                "mode": plan.mode,
                "panic": self.emergency.is_panic(),
                "vpn_iface": vpn_state.iface,
            }, sort_keys=True)

            if signature != self._last_signature:
                logger.info(
                    "Network state changed — mode=%s, panic=%s",
                    plan.mode, self.emergency.is_panic(),
                )
                if plan.mode != "error" and not vpn_state.conflict:
                    self.firewall.activate(plan)
                self._last_signature = signature

            state = ControllerState(
                mode=plan.mode,
                firewall_active=self.firewall.is_active(),
                reason=plan.reason,
                physical_ifaces=tuple(i.name for i in snapshot.physical_ifaces),
                vpn_iface=vpn_state.iface,
                vpn_provider=vpn_state.provider,
                route_probe_iface=snapshot.route_probe_iface,
                dns_servers=snapshot.dns_servers,
                dns_servers_v6=snapshot.dns_servers_v6,
                proton_native_killswitch=vpn_state.proton_native_killswitch,
                panic_mode=self.emergency.is_panic(),
            )
            self._write_status_file(state)
            self._last_state = state
            return state

        except Exception as e:
            logger.exception("Daemon sync failed: %s", _sanitize_error(e))
            self.emergency.trigger_panic(f"Internal error: {_sanitize_error(e)}")
            # Ensure we fail closed on error by applying panic rules directly
            try:
                panic_plan = FirewallPlan(
                    self.firewall._render_panic_rules(),
                    "panic",
                    "FAIL CLOSED: Internal error triggered panic.",
                )
                self.firewall.activate(panic_plan)
            except Exception as inner:
                logger.error(
                    "Failed to apply panic rules during error recovery: %s",
                    _sanitize_error(inner),
                )
            state = ControllerState(
                mode="panic",
                firewall_active=True,
                reason="Internal error — FAIL CLOSED engaged.",
                physical_ifaces=(),
                vpn_iface=None,
                vpn_provider="unknown",
                route_probe_iface=None,
                dns_servers=(),
                dns_servers_v6=(),
                proton_native_killswitch=False,
                panic_mode=True,
            )
            self._write_status_file(state)
            self._last_state = state
            return state

    def disable(self) -> None:
        """
        Disables panic mode and forces a re-sync.
        SEC-DAEMON-01: Removed firewall.deactivate() which would leave the
        system unprotected (empty ruleset). We instead rely on the next sync()
        to calculate the safe set of rules.
        """
        self.emergency.disable_panic()
        self._last_signature = None
        self.sync()

    def trigger_panic(self) -> None:
        self.emergency.trigger_panic("Manual panic triggered by user")
        self.sync()

    # ------------------------------------------------------------------
    # IPC handlers (CRIT-04)
    # ------------------------------------------------------------------
    def _ipc_panic(self) -> dict:
        self.trigger_panic()
        return {"mode": "panic", "message": "Panic mode engaged."}

    def _ipc_panic_disable(self) -> dict:
        self.emergency.disable_panic()
        self._last_signature = None  # force re-evaluation on next sync
        return {"message": "Panic mode disabled. Next sync will re-evaluate."}

    def _ipc_status(self) -> dict:
        if self._last_state:
            return asdict(self._last_state)
        return {"mode": "unknown", "message": "No sync has completed yet."}

    # ------------------------------------------------------------------
    # PID file (LOW-04)
    # ------------------------------------------------------------------
    _PID_PATH = "/run/ghosttunnel/ghostd.pid"

    def _write_pid(self) -> None:
        try:
            Path(self._PID_PATH).parent.mkdir(parents=True, exist_ok=True)
            Path(self._PID_PATH).write_text(str(os.getpid()), encoding="ascii")
            os.chmod(self._PID_PATH, 0o644)
            logger.debug("PID file written: %s (pid=%d)", self._PID_PATH, os.getpid())
        except OSError as exc:
            logger.warning("Could not write PID file: %s", exc)

    def _remove_pid(self) -> None:
        try:
            Path(self._PID_PATH).unlink(missing_ok=True)
        except OSError:
            pass

    def run(self):
        logger.info("Starting GhostTunnel Daemon...")
        self._running = True

        # LOW-04: Write PID file immediately
        self._write_pid()

        # CRIT-01: Lock down before first poll
        self._apply_boot_rules()

        # CRIT-04: Start IPC server
        self._ipc = IpcServer({
            "panic": self._ipc_panic,
            "panic-disable": self._ipc_panic_disable,
            "status": self._ipc_status,
        })
        self._ipc.start()

        def handle_signal(signum, frame):
            logger.info("Received termination signal.")
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        while self._running:
            try:
                self.sync()
            except Exception as e:
                # Final safety net — should never reach here
                logger.critical("Unhandled exception in daemon loop: %s", _sanitize_error(e))
            time.sleep(self.settings.monitor_poll_seconds)

        # Cleanup
        if self._ipc:
            self._ipc.stop()
        self._remove_pid()
        logger.info("Daemon stopped.")

    # ------------------------------------------------------------------
    # Status file (HIGH-01: permissions 0o640)
    # ------------------------------------------------------------------
    def _write_status_file(self, state: ControllerState) -> None:
        path = Path(self.settings.status_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(asdict(state), indent=2)
        try:
            fd, tmp = tempfile.mkstemp(
                dir=str(path.parent), prefix=".status-", suffix=".tmp"
            )
            try:
                os.write(fd, content.encode("utf-8"))
            finally:
                os.close(fd)
            os.chmod(tmp, 0o640)   # HIGH-01: restrict to owner + group only
            os.replace(tmp, str(path))
        except OSError as exc:
            # Do NOT fall back to a non-atomic write — a half-written status
            # file is misleading. Just log and move on.
            logger.warning("Failed to write status file atomically: %s", exc)


def main():
    import ghosttunnel.core.logger as log_setup
    log_setup.setup_logger("ghosttunnel.daemon")

    settings = Settings.load()
    daemon = GhostDaemon(settings)
    daemon.run()


if __name__ == "__main__":
    main()
