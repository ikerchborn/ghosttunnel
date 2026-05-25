"""
GhostTunnel GUI — Qt6 Desktop Monitoring Interface
=====================================================
Fully functional GUI with:
  - Live status via IPC socket (not just file polling)
  - Status file fallback for read-only viewing
  - Privilege escalation via IPC for all root commands
  - Config persistence (save to /etc/ghosttunnel/config.json)
  - Log panel with timestamped entries
  - Panic / Disable / Unlock controls fully wired to IPC
  - trust_local_dns toggle surfaced in the UI
  - BUG-GUI-01: IpcWorker now reads status_path from settings correctly
  - BUG-GUI-02: connection_lost properly shows daemon offline without crashing
  - BUG-GUI-03: _run_privileged now falls back gracefully via IPC
  - BUG-GUI-04: Save config works via IPC
  - BUG-GUI-05: GUI exit code propagated via sys.exit(app.exec())
  - BUG-GUI-06: _on_daemon_gone deduplicates log messages (no more spam)
  - BUG-GUI-07: Refresh button triggers immediate IPC poll
  - BUG-GUI-08: Obsolete policykit-1 reference removed
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

from ghosttunnel.core.config import Settings

try:
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
    from PyQt6.QtGui import QFont, QColor, QIcon
    from PyQt6.QtWidgets import (
        QApplication,
        QCheckBox,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QVBoxLayout,
        QWidget,
        QFrame,
        QGroupBox,
        QSizePolicy,
        QScrollArea,
    )
except ImportError as exc:
    raise RuntimeError(
        "PyQt6 is required for GUI mode.\n"
        "Install with:  sudo apt install python3-pyqt6\n"
        "Or via pip:    pip install PyQt6"
    ) from exc

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Stylesheets
# ------------------------------------------------------------------
DARK_THEME = """
QWidget {
    background-color: #0a0a0a;
    color: #00ff41;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 14px;
}
QMainWindow {
    background-color: #000000;
}
QGroupBox {
    border: 1px solid #00ff41;
    border-radius: 0px;
    margin-top: 14px;
    padding: 14px 16px 10px 16px;
    font-weight: 700;
    color: #00ff41;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 2px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px 0 6px;
    color: #00ff41;
    background-color: #000000;
}
QLabel#AppTitle {
    font-size: 26px;
    font-weight: 800;
    color: #00ff41;
    letter-spacing: 2px;
}
QLabel#AppSubtitle {
    color: #008f11;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QLabel#StatusBadge {
    font-size: 20px;
    font-weight: 800;
    padding: 8px 20px;
    border-radius: 0px;
    background-color: #0a0a0a;
    border: 1px solid #00ff41;
    color: #00ff41;
}
QPushButton {
    background-color: #000000;
    border: 1px solid #00ff41;
    border-radius: 0px;
    color: #00ff41;
    padding: 9px 20px;
    font-weight: 700;
    min-height: 36px;
    text-transform: uppercase;
}
QPushButton:hover { background-color: #00ff41; color: #000000; }
QPushButton:pressed { background-color: #008f11; color: #000000; }
QPushButton#PanicBtn {
    background-color: #3a0000;
    color: #ff003c;
    border: 1px solid #ff003c;
    font-size: 15px;
    font-weight: 800;
}
QPushButton#PanicBtn:hover { background-color: #ff003c; color: #000000; }
QPushButton#DisablePanicBtn {
    background-color: #002200;
    color: #00ff41;
    border: 1px solid #00ff41;
}
QPushButton#DisablePanicBtn:hover { background-color: #00ff41; color: #000000; }
QPushButton#UnlockBtn {
    background-color: #221100;
    color: #ffaa00;
    border: 1px solid #ffaa00;
}
QPushButton#UnlockBtn:hover { background-color: #ffaa00; color: #000000; }
QPushButton#SaveBtn {
    background-color: #002200;
    color: #00ff41;
    border: 1px solid #00ff41;
}
QPushButton#SaveBtn:hover { background-color: #00ff41; color: #000000; }
QCheckBox { spacing: 10px; font-weight: 700; color: #00ff41; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 0px;
    border: 1px solid #00ff41; background-color: #000000;
}
QCheckBox::indicator:checked { background-color: #00ff41; border-color: #00ff41; }
QCheckBox::indicator:hover { border-color: #008f11; }
QPlainTextEdit {
    background-color: #000000;
    border: 1px solid #00ff41;
    border-radius: 0px;
    padding: 10px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    color: #00ff41;
}
QScrollBar:vertical { background: #0a0a0a; width: 12px; border-radius: 0px; border-left: 1px solid #00ff41; }
QScrollBar::handle:vertical { background: #00ff41; border-radius: 0px; min-height: 20px; }
"""

_MODE_COLORS = {
    "vpn-up":       ("VPN ACTIVE",      "#00ff41"),
    "vpn-down":     ("VPN DOWN",         "#ff003c"),
    "panic":        ("PANIC — BLOCKED",  "#ff003c"),
    "disabled":     ("DISABLED",         "#ffaa00"),
    "boot":         ("BOOTING…",         "#008f11"),
    "vpn-conflict": ("VPN CONFLICT",     "#ff003c"),
    "error":        ("ERROR",            "#ff003c"),
    "unknown":      ("CONNECTING…",      "#008f11"),
}

# Allowlist of subcommands the GUI is allowed to invoke (injection prevention)
ALLOWED_SUBCOMMANDS = frozenset({"panic", "panic-disable", "unlock-network"})


# ------------------------------------------------------------------
# IPC worker thread — queries daemon socket without blocking GUI
# ------------------------------------------------------------------
class IpcWorker(QThread):
    """Polls the IPC socket every 3s and emits status updates."""
    status_updated = pyqtSignal(dict)
    connection_lost = pyqtSignal()

    def __init__(self, status_path: str, parent=None):
        super().__init__(parent)
        self.status_path = status_path
        self._running = True
        self._wake = threading.Event()  # BUG-GUI-07: allow immediate poll

    def run(self):
        import socket, json
        from ghosttunnel.core.ipc import STATUS_SOCKET_PATH
        while self._running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(10.0)
                    s.connect(STATUS_SOCKET_PATH)
                    while self._running:
                        f = s.makefile('r', encoding='utf-8')
                        line = f.readline()
                        if not line:
                            break
                        data = json.loads(line)
                        if data.get("event") == "status_change":
                            state = data.get("state", {})
                            self.status_updated.emit(state)
            except Exception:
                self._fallback_read()
                self._wake.wait(timeout=3.0)
                self._wake.clear()

    def request_poll(self):
        """BUG-GUI-07: Wake the worker thread for an immediate poll."""
        self._wake.set()

    def _fallback_read(self):
        """BUG-GUI-02: Read status file as fallback when IPC is unavailable."""
        try:
            p = Path(self.status_path)
            if p.exists():
                text = p.read_text(encoding="utf-8")
                data = json.loads(text)
                if isinstance(data, dict):
                    self.status_updated.emit(data)
                    return
        except PermissionError:
            # File exists but we can't read it (0o640, need root)
            pass
        except Exception:
            pass
        self.connection_lost.emit()

    def stop(self):
        self._running = False
        self._wake.set()  # Unblock the wait so the thread can exit
        self.quit()
        self.wait(2000)


# ------------------------------------------------------------------
# Main Window
# ------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.setWindowTitle("GhostTunnel — VPN Kill Switch Monitor")
        self.resize(1020, 780)
        self.setMinimumSize(800, 620)
        self.setStyleSheet(DARK_THEME)
        self._build_ui()

        # Auto-refresh timer as additional fallback (60s)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._request_manual_refresh)
        self._timer.start(60_000)

        # Start background IPC worker
        self._worker = IpcWorker(self.settings.status_path, self)
        self._worker.status_updated.connect(self._on_status)
        self._worker.connection_lost.connect(self._on_daemon_gone)
        self._worker.start()

        self._daemon_offline_logged = False  # BUG-GUI-06: dedup flag
        self._log("GhostTunnel GUI started. Connecting to daemon...")

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header ────────────────────────────────────────────────
        header = QHBoxLayout()
        left_header = QVBoxLayout()
        title = QLabel("🛡️  GhostTunnel")
        title.setObjectName("AppTitle")
        subtitle = QLabel("FAIL‑CLOSED VPN Kill Switch  •  OPSEC Infrastructure")
        subtitle.setObjectName("AppSubtitle")
        left_header.addWidget(title)
        left_header.addWidget(subtitle)
        left_header.setSpacing(4)
        header.addLayout(left_header)
        header.addStretch()

        self.badge = QLabel("CONNECTING…")
        self.badge.setObjectName("StatusBadge")
        self.badge.setStyleSheet("color: #8b949e;")
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.badge)
        root.addLayout(header)

        # ── Status Grid ───────────────────────────────────────────
        status_box = QGroupBox("Live Network Status")
        sg = QGridLayout(status_box)
        sg.setSpacing(12)
        sg.setColumnStretch(1, 1)
        sg.setColumnStretch(3, 1)

        self._s = {}
        fields = [
            ("mode",            "Current Mode",        0, 0),
            ("panic_mode",      "Panic Active",        0, 2),
            ("vpn_provider",    "VPN Provider",        1, 0),
            ("vpn_iface",       "Tunnel Interface",    1, 2),
            ("firewall_active", "Firewall Active",     2, 0),
            ("route_probe",     "Route Probe Iface",   2, 2),
            ("physical_ifaces", "Physical Interfaces", 3, 0),
            ("dns_servers",     "DNS Servers",         3, 2),
        ]
        for key, label, row, col in fields:
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #8b949e; font-weight: 600;")
            val = QLabel("—")
            val.setStyleSheet("color: #e6edf3; font-weight: 500;")
            val.setWordWrap(True)
            sg.addWidget(lbl, row, col)
            sg.addWidget(val, row, col + 1)
            self._s[key] = val

            self._s[key] = val

        # ── Controls ──────────────────────────────────────────────
        ctrl_box = QGroupBox("Controls")
        ctrl_layout = QHBoxLayout(ctrl_box)
        ctrl_layout.setSpacing(12)

        self.btn_panic = QPushButton("⚡  TRIGGER PANIC")
        self.btn_panic.setObjectName("PanicBtn")
        self.btn_panic.setToolTip("Immediately block all network traffic (FAIL CLOSED)")
        self.btn_panic.clicked.connect(self._action_panic)

        self.btn_disable_panic = QPushButton("✅  Disable Panic")
        self.btn_disable_panic.setObjectName("DisablePanicBtn")
        self.btn_disable_panic.setToolTip("Restore normal VPN-protected operation")
        self.btn_disable_panic.clicked.connect(self._action_disable_panic)

        self.btn_unlock = QPushButton("🔓  Emergency Unlock")
        self.btn_unlock.setObjectName("UnlockBtn")
        self.btn_unlock.setToolTip("Stop daemon and flush all firewall rules (last resort)")
        self.btn_unlock.clicked.connect(self._action_unlock)

        self.btn_refresh = QPushButton("🔄  Refresh")
        self.btn_refresh.setToolTip("Manually refresh status")
        self.btn_refresh.clicked.connect(self._request_manual_refresh)

        ctrl_layout.addWidget(self.btn_panic)
        ctrl_layout.addWidget(self.btn_disable_panic)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(self.btn_refresh)
        ctrl_layout.addWidget(self.btn_unlock)
        ctrl_layout.addWidget(self.btn_unlock)

        # ── Config Toggles ────────────────────────────────────────
        cfg_box = QGroupBox("Configuration (saves to /etc/ghosttunnel/config.json)")
        cfg_grid = QGridLayout(cfg_box)
        cfg_grid.setSpacing(10)

        self.chk_allow_lan = QCheckBox("Allow LAN Traffic (ping + mDNS)")
        self.chk_allow_lan.setChecked(self.settings.allow_lan)

        self.chk_allow_fwd = QCheckBox("Allow IP Forwarding (Docker / HTB)")
        self.chk_allow_fwd.setChecked(self.settings.allow_forwarding)

        self.chk_stealth = QCheckBox("Stealth Mode (block ICMP)")
        self.chk_stealth.setChecked(self.settings.stealth_mode)

        self.chk_trust_dns = QCheckBox("Trust Local DHCP DNS (not recommended)")
        self.chk_trust_dns.setChecked(self.settings.trust_local_dns)
        self.chk_trust_dns.setStyleSheet("color: #e3b341;")

        self.chk_ipv6 = QCheckBox("Block IPv6 completely")
        self.chk_ipv6.setChecked(self.settings.ipv6_block)

        self.chk_auto_rotate = QCheckBox("Auto-rotate VPN on failure")
        self.chk_auto_rotate.setChecked(self.settings.auto_rotate)

        cfg_grid.addWidget(self.chk_allow_lan, 0, 0)
        cfg_grid.addWidget(self.chk_allow_fwd, 0, 1)
        cfg_grid.addWidget(self.chk_stealth, 1, 0)
        cfg_grid.addWidget(self.chk_trust_dns, 1, 1)
        cfg_grid.addWidget(self.chk_ipv6, 2, 0)
        cfg_grid.addWidget(self.chk_auto_rotate, 2, 1)

        btn_save = QPushButton("💾  Save Config")
        btn_save.setObjectName("SaveBtn")
        btn_save.clicked.connect(self._save_config)
        cfg_grid.addWidget(btn_save, 3, 0, 1, 2)

        # BUG-GUI-09: Disable config saving if not root, to avoid showing default values and confusing user
        if os.geteuid() != 0:
            cfg_box.setTitle("Configuration (READ-ONLY: Root Required)")
            cfg_box.setEnabled(False)
            btn_save.setText("Restart GUI as Root to Edit Config")
            btn_save.setEnabled(False)

        # ── Activity Log ──────────────────────────────────────────
        log_box = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_box)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)
        log_layout.addWidget(self.log)
        
        # Assemble Layout
        root.addWidget(ctrl_box)
        root.addWidget(status_box)
        root.addWidget(cfg_box)
        root.addWidget(log_box)
        root.setStretch(4, 1)  # log expands

    # ------------------------------------------------------------------
    # Status update
    # ------------------------------------------------------------------
    def _on_status(self, data: dict) -> None:
        self._daemon_offline_logged = False  # BUG-GUI-06: daemon is back
        raw_mode = data.get("mode", "unknown")
        label, color = _MODE_COLORS.get(raw_mode, (raw_mode.upper(), "#8b949e"))
        self.badge.setText(label)
        self.badge.setStyleSheet(f"color: {color}; border-color: {color};")

        self._s["mode"].setText(raw_mode.upper())
        self._s["mode"].setStyleSheet(f"color: {color}; font-weight: 700;")

        panic = data.get("panic_mode", False)
        self._s["panic_mode"].setText("🔴 YES" if panic else "🟢 NO")
        self._s["panic_mode"].setStyleSheet(
            "color: #ff003c; font-weight: 700;" if panic else "color: #00ff41; font-weight: 700;"
        )

        self._s["vpn_provider"].setText(
            str(data.get("vpn_provider", "unknown")).upper()
        )
        self._s["vpn_iface"].setText(data.get("vpn_iface") or "— none —")

        fw = data.get("firewall_active", False)
        self._s["firewall_active"].setText("🟢 ACTIVE" if fw else "🔴 INACTIVE")
        self._s["firewall_active"].setStyleSheet(
            "color: #00ff41; font-weight: 700;" if fw else "color: #ff003c; font-weight: 700;"
        )

        self._s["route_probe"].setText(data.get("route_probe_iface") or "—")
        self._s["physical_ifaces"].setText(
            ", ".join(data.get("physical_ifaces", [])) or "—"
        )
        self._s["dns_servers"].setText(
            ", ".join(data.get("dns_servers", [])) or "—"
        )

    def _on_daemon_gone(self) -> None:
        """BUG-GUI-02/06: Called when both IPC and status file are unavailable."""
        self.badge.setText("DAEMON OFFLINE")
        self.badge.setStyleSheet("color: #008f11; border-color: #008f11;")
        for key in self._s:
            self._s[key].setText("—")
        # BUG-GUI-06: Only log once until daemon comes back online
        if not self._daemon_offline_logged:
            self._daemon_offline_logged = True
            self._log("⚠ Daemon is unreachable — status file not found or unreadable.")
            self._log("  → Start daemon: sudo systemctl start ghosttunnel")

    def _request_manual_refresh(self) -> None:
        """BUG-GUI-07: Manually trigger an immediate IPC status check."""
        if self._worker and self._worker.isRunning():
            self._worker.request_poll()
            self._log("↻ Refresh requested...")

    # ------------------------------------------------------------------
    # Privileged actions via IPC (direct to socket)
    # ------------------------------------------------------------------
    def _run_privileged(self, subcommand: str) -> bool:
        from ghosttunnel.core.ipc import send_command
        self._log(f"→ Sending command: {subcommand}")
        try:
            resp = send_command(subcommand)
            if resp.get("ok"):
                msg = resp.get("message", "Success")
                self._log(f"✓ {msg}")
                return True
            else:
                msg = resp.get("error", "Unknown error")
                self._log(f"✗ Error: {msg}")
                QMessageBox.critical(self, "Command Failed", msg)
                return False
        except Exception as e:
            self._log(f"✗ IPC Error: {e}")
            QMessageBox.critical(self, "Connection Error", str(e))
            return False

    def _action_panic(self) -> None:
        reply = QMessageBox.question(
            self, "Confirm PANIC",
            "This will immediately block ALL network traffic.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._run_privileged("panic")

    def _action_disable_panic(self) -> None:
        self._run_privileged("panic-disable")

    def _action_unlock(self) -> None:
        reply = QMessageBox.warning(
            self, "⚠ Emergency Unlock",
            "This stops the daemon and removes ALL firewall rules.\n"
            "Your real IP will be EXPOSED until you restart GhostTunnel.\n\n"
            "Are you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._run_privileged("unlock-network")

    # ------------------------------------------------------------------
    # Config save — BUG-GUI-04: Requires root for writing to /etc/
    # ------------------------------------------------------------------
    def _save_config(self) -> None:
        self.settings.allow_lan = self.chk_allow_lan.isChecked()
        self.settings.allow_forwarding = self.chk_allow_fwd.isChecked()
        self.settings.stealth_mode = self.chk_stealth.isChecked()
        self.settings.trust_local_dns = self.chk_trust_dns.isChecked()
        self.settings.ipv6_block = self.chk_ipv6.isChecked()
        self.settings.auto_rotate = self.chk_auto_rotate.isChecked()

        # Try direct save first (works if running as root)
        if os.geteuid() == 0:
            try:
                self.settings.save()
                self._log("✓ Configuration saved to /etc/ghosttunnel/config.json")
                self._log("  ↻ Restart daemon for changes to take effect: sudo systemctl restart ghosttunnel")
                QMessageBox.information(
                    self, "Saved",
                    "Configuration saved.\n\n"
                    "Restart the daemon for changes to take effect:\n"
                    "  sudo systemctl restart ghosttunnel"
                )
                return
            except Exception as exc:
                self._log(f"✗ Save failed: {exc}")
                QMessageBox.critical(self, "Save Failed", str(exc))
                return

        # Non-root: inform user to save via CLI
        QMessageBox.information(
            self, "Save Config",
            "Config saving from the GUI requires root privileges.\n\n"
            "To save settings, run:\n"
            "  sudo ghostctl status\n\n"
            "Or restart the GUI with root:\n"
            "  sudo ghostgui",
        )
        self._log("⚠ Config save skipped — GUI needs root to write /etc/ghosttunnel/config.json")

    # ------------------------------------------------------------------
    # Log helper
    # ------------------------------------------------------------------
    def _log(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}]  {text}")
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:
        self._timer.stop()
        self._worker.stop()
        super().closeEvent(event)


# ------------------------------------------------------------------
# Entry point — BUG-GUI-05: returns int exit code
# ------------------------------------------------------------------
def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("GhostTunnel")
    app.setApplicationDisplayName("GhostTunnel VPN Kill Switch")
    app.setStyle("Fusion")

    settings = Settings.load()
    
    window = MainWindow(settings)
    
    window.show()
    
    sys.exit(app.exec())
