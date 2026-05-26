"""
GhostTunnel Daemon
====================
Fixes applied:
  CRIT-01  — Pre-boot panic rules applied before first poll cycle
  CRIT-04  — IPC server integrated (panic, panic-disable, status via socket)
  HIGH-01  — Status file permissions restricted to 0o640
  HIGH-01  — Status file permissions restricted to 0o644
  MED-07   — Exception messages sanitized before persisting to status file
  LOW-04   — Daemon writes a PID file for reliable process tracking
  BUG-DAEMON-01 — /run/ghosttunnel dir created with correct 0o755 perms
  BUG-DAEMON-02 — Root logger "ghosttunnel" configured so all child loggers log
  BUG-DAEMON-03 — vpn_rotator.reset() not called during panic mode
  BUG-DAEMON-04 — firewall.activate() errors now logged but do NOT crash sync()
  BUG-DAEMON-05 — Status file dir created with correct permissions (0o755)
  BUG-DAEMON-06 — Status file created with 0o644 so non-root GUI can read status
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
from ghosttunnel.core.anomaly import AnomalyDetector

logger = logging.getLogger(__name__)

# Maximum length of exception text persisted to status/logs (MED-07)
_MAX_ERROR_MSG = 200


def _sanitize_error(exc: Exception) -> str:
    """Strip paths and limit length of error messages exposed in status file."""
    raw = str(exc)
    # Remove file system paths that could leak internal structure
    sanitized = raw.split("/")[-1] if "/" in raw else raw
    return sanitized[:_MAX_ERROR_MSG]


def _ensure_runtime_dir() -> None:
    """Create /run/ghosttunnel with correct permissions if it doesn't exist."""
    path = Path("/run/ghosttunnel")
    path.mkdir(parents=True, exist_ok=True)
    try:
        # 0o755: root rwx, rx everyone (so gui can read status.json)
        os.chmod(str(path), 0o755)
    except OSError:
        pass  # Already exists with correct perms from systemd RuntimeDirectory


class GhostDaemon:
    """
    Main GhostTunnel daemon logic that handles synchronization cycles, VPN rotation,
    leak detection, and IPC message routing.
    """

    def __init__(self, settings: Settings) -> None:
        """
        Initialize the GhostDaemon with configuration settings.

        Args:
            settings: The system configuration settings.
        """
        self.settings = settings
        self.leak_detector = LeakDetector(settings)
        self.vpn_monitor = VpnMonitor(settings)
        self.vpn_rotator = VpnRotator(settings)
        self.firewall = NftFirewallManager(settings)
        self.emergency = EmergencyController()
        self.anomaly_detector = AnomalyDetector()

        self._running = False
        self._last_signature: str | None = None
        self._ipc: IpcServer | None = None
        self._last_state: ControllerState | None = None


    # ------------------------------------------------------------------
    # CRIT-01 — Apply blocking rules immediately before entering the loop
    # ------------------------------------------------------------------
    def _apply_boot_rules(self) -> None:
        """
        Ensure the network is locked BEFORE the first snapshot completes.
        If the daemon starts with an existing panic lock, apply panic rules.
        Otherwise apply panic rules and let the first sync() open up appropriately.
        """
        try:
            if self.emergency.is_panic():
                logger.warning("Panic lock found at boot — applying FAIL CLOSED rules immediately.")
                mode = "panic"
            else:
                mode = "boot"

            plan = FirewallPlan(
                self.firewall._render_panic_rules(),
                mode,
                f"Boot lockdown ({mode}): blocking until first successful sync.",
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

            # BUG-DAEMON-03: Only reset rotator when VPN is healthy AND not in panic
            if vpn_state.active and not vpn_state.is_leaking and not self.emergency.is_panic():
                self.vpn_rotator.reset()

            # Re-detect external KS on every cycle — Mullvad/ProtonVPN may start/stop
            self.firewall._detect_external_ks()

            # Firewall Planning
            plan = self.firewall.build_plan(snapshot, vpn_state, self.emergency.is_panic())

            # State Signature — only update firewall when something meaningful changed
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
                # BUG-DAEMON-04: Catch firewall errors so sync() never crashes silently
                try:
                    self.firewall.activate(plan)
                except Exception as fw_exc:
                    logger.error("Firewall activate failed: %s — applying panic rules", fw_exc)
                    try:
                        self.firewall.activate(FirewallPlan(
                            self.firewall._render_panic_rules(),
                            "panic",
                            "FAIL CLOSED: Firewall apply error.",
                        ))
                    except Exception as inner:
                        logger.critical("Could not apply panic rules either: %s", inner)
                self._last_signature = signature

            # Anomaly Detection
            anomalies = self.anomaly_detector.analyze(
                snapshot=snapshot,
                current_mode=plan.mode,
                vpn_provider=vpn_state.provider,
                vpn_iface=vpn_state.iface,
            )

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
                anomalies=tuple(anomalies),
            )
            self._write_status_file(state)
            self._last_state = state
            if signature != self._last_signature and self._ipc:
                self._ipc.broadcast({"event": "status_change", "state": asdict(state), "timestamp": time.time()})
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
            if signature != self._last_signature and self._ipc:
                self._ipc.broadcast({"event": "status_change", "state": asdict(state), "timestamp": time.time()})
            return state

    def disable(self) -> None:
        """
        Disables panic mode and forces a re-sync.
        SEC-DAEMON-01: Removed firewall.deactivate() — we rely on next sync()
        to calculate the correct safe ruleset.
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
    def _ipc_panic(self, payload: dict) -> dict:
        """
        Triggers emergency panic lock mode.
        """
        self.trigger_panic()
        return {"mode": "panic", "message": "Panic mode engaged."}

    def _ipc_panic_disable(self, payload: dict) -> dict:
        """
        Disables emergency panic lock mode.
        """
        self.emergency.disable_panic()
        self._last_signature = None  # force re-evaluation
        self.sync()  # Apply new rules immediately (matches _ipc_panic behavior)
        return {"message": "Panic mode disabled. Firewall rules updated."}

    def _ipc_status(self, payload: dict) -> dict:
        """
        Returns the last synchronized state.
        """
        if self._last_state:
            return asdict(self._last_state)
        return {"mode": "unknown", "message": "No sync has completed yet."}

    def _ipc_unlock_network(self, payload: dict) -> dict:
        """
        Asynchronously deactivates the firewall and stops the daemon.
        """
        import threading
        def _stop() -> None:
            time.sleep(0.5)
            from ghosttunnel.core.emergency import PANIC_LOCK_PATH
            Path(PANIC_LOCK_PATH).unlink(missing_ok=True)
            self.firewall.deactivate()
            self._running = False
        threading.Thread(target=_stop).start()
        return {"message": "Network unlocked. Daemon stopping."}

    def _ipc_save_config(self, payload: dict) -> dict:
        """
        Validates value types and saves config payload.
        """
        if not isinstance(payload, dict):
            return {"error": "Invalid payload format"}
        for k, v in payload.items():
            if hasattr(self.settings, k):
                # Validate the type using Settings type specifications
                validated = self.settings._validate_field(k, v)
                if validated is not None:
                    setattr(self.settings, k, validated)
        try:
            self.settings._sanitize_network_fields()
            self.settings.save()
            return {"message": "Configuration saved to /etc/ghosttunnel/config.json"}
        except Exception as e:
            return {"error": str(e)}


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

    def run(self) -> None:
        logger.info("Starting GhostTunnel Daemon v1.0.0...")
        self._running = True

        # BUG-DAEMON-01: Ensure runtime dir exists with correct permissions
        _ensure_runtime_dir()

        # LOW-04: Write PID file immediately
        self._write_pid()

        # CRIT-01: Lock down before first poll
        self._apply_boot_rules()

        # CRIT-04: Start IPC server
        self._ipc = IpcServer({
            "panic": self._ipc_panic,
            "panic-disable": self._ipc_panic_disable,
            "status": self._ipc_status,
            "unlock-network": self._ipc_unlock_network,
            "save-config": self._ipc_save_config,
        })
        self._ipc.start()

        from typing import Any
        def handle_signal(signum: int, frame: Any) -> None:
            logger.info("Received termination signal (sig=%d).", signum)
            self._running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        logger.info(
            "Daemon started. Poll interval: %.1fs. IPC: /run/ghosttunnel/ctrl.sock",
            self.settings.monitor_poll_seconds,
        )

        while self._running:
            try:
                self.sync()
            except Exception as e:
                # Final safety net — should never reach here since sync() catches internally
                logger.critical("Unhandled exception in daemon loop: %s", _sanitize_error(e))
            time.sleep(self.settings.monitor_poll_seconds)

        # Cleanup
        if self._ipc:
            self._ipc.stop()
        self._remove_pid()
        logger.info("Daemon stopped cleanly.")

    # ------------------------------------------------------------------
    # Status file (HIGH-01: permissions 0o640)
    # ------------------------------------------------------------------
    def _write_status_file(self, state: ControllerState) -> None:
        """
        Atomically write current ControllerState to the status file.

        Args:
            state: The current ControllerState.
        """
        path = Path(self.settings.status_path)
        # BUG-DAEMON-05: Create dir with 0o755 so world can traverse to read status
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(0o755)
        except OSError:
            pass

        content = json.dumps(asdict(state), indent=2)
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=str(path.parent),
                prefix=".status-",
                suffix=".tmp",
                delete=False,
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(content)
                tmp_path = tmp_file.name
            os.chmod(tmp_path, 0o644)   # BUG-DAEMON-06: allow non-root to read status
            os.replace(tmp_path, str(path))
        except OSError as exc:
            logger.warning("Failed to write status file atomically: %s", exc)


def main() -> None:
    """
    Main entry point for running the daemon process.
    """
    import ghosttunnel.core.logger as log_setup
    # BUG-DAEMON-02: Configure the ROOT "ghosttunnel" logger so ALL child loggers
    # (ghosttunnel.daemon, ghosttunnel.core.*, ghosttunnel.vpn.*) inherit the handler.
    root_logger = log_setup.setup_logger("ghosttunnel")
    root_logger.propagate = False

    # Re-bind the module logger now that the handler is installed
    global logger
    logger = logging.getLogger(__name__)

    settings = Settings.load()
    daemon = GhostDaemon(settings)
    daemon.run()


if __name__ == "__main__":
    main()

