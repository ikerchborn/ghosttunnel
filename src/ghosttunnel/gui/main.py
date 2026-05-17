"""
GhostTunnel GUI — Qt6 Desktop Monitoring Interface
=====================================================
Fully functional GUI with:
  - Live status via IPC socket (not just file polling)
  - Status file fallback for read-only viewing
  - Privilege escalation via pkexec for all root commands
  - Config persistence (save to /etc/ghosttunnel/config.json)
  - Log panel with timestamped entries
  - Panic / Disable / Unlock controls fully wired to IPC
  - trust_local_dns toggle surfaced in the UI
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
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
        "PyQt6 is required for GUI mode. Install with: apt install python3-pyqt6"
    ) from exc

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Stylesheets
# ------------------------------------------------------------------
DARK_THEME = """
QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Inter', 'Segoe UI', sans-serif;
    font-size: 14px;
}
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #090c10, stop:1 #161b22);
}
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 10px;
    margin-top: 14px;
    padding: 14px 16px 10px 16px;
    font-weight: 700;
    color: #8b949e;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px 0 6px;
    color: #8b949e;
}
QLabel#AppTitle {
    font-size: 24px;
    font-weight: 800;
    color: #58a6ff;
}
QLabel#AppSubtitle {
    color: #8b949e;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QLabel#StatusBadge {
    font-size: 20px;
    font-weight: 800;
    padding: 8px 20px;
    border-radius: 8px;
    background-color: rgba(31,35,40,0.6);
    border: 1px solid #30363d;
}
QPushButton {
    background-color: #21262d;
    border: 1px solid #363b42;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 9px 20px;
    font-weight: 600;
    min-height: 36px;
}
QPushButton:hover { background-color: #30363d; border-color: #8b949e; }
QPushButton:pressed { background-color: #1c2128; }
QPushButton#PanicBtn {
    background-color: #da3633;
    color: white;
    border: 1px solid rgba(240,246,252,0.15);
    font-size: 15px;
    font-weight: 700;
}
QPushButton#PanicBtn:hover { background-color: #f85149; }
QPushButton#DisablePanicBtn {
    background-color: #1f6feb;
    color: white;
    border: 1px solid rgba(240,246,252,0.15);
}
QPushButton#DisablePanicBtn:hover { background-color: #388bfd; }
QPushButton#UnlockBtn {
    background-color: #3d1f00;
    color: #e3b341;
    border: 1px solid #7d4e00;
}
QPushButton#UnlockBtn:hover { background-color: #4d2900; }
QPushButton#SaveBtn {
    background-color: #238636;
    color: white;
    border: 1px solid rgba(240,246,252,0.1);
}
QPushButton#SaveBtn:hover { background-color: #2ea043; }
QCheckBox { spacing: 10px; font-weight: 500; color: #c9d1d9; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 4px;
    border: 1px solid #30363d; background-color: #0d1117;
}
QCheckBox::indicator:checked { background-color: #58a6ff; border-color: #58a6ff; }
QCheckBox::indicator:hover { border-color: #8b949e; }
QPlainTextEdit {
    background-color: #010409;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 10px;
    font-family: 'Consolas', 'JetBrains Mono', 'Courier New', monospace;
    font-size: 12px;
    color: #3fb950;
}
QScrollBar:vertical { background: #0d1117; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; min-height: 20px; }
"""

_MODE_COLORS = {
    "vpn-up":      ("VPN ACTIVE",      "#3fb950"),
    "vpn-down":    ("VPN DOWN",         "#f85149"),
    "panic":       ("PANIC — BLOCKED",  "#f85149"),
    "disabled":    ("DISABLED",         "#e3b341"),
    "boot":        ("BOOTING…",         "#8b949e"),
    "vpn-conflict":("VPN CONFLICT",     "#f85149"),
    "error":       ("ERROR",            "#f85149"),
}


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

    def run(self):
        from ghosttunnel.core.ipc import send_command, SOCKET_PATH
        while self._running:
            try:
                data = send_command("status", timeout=3.0)
                self.status_updated.emit(data)
            except Exception:
                # Fallback: read status file
                try:
                    p = Path(self.status_path)
                    if p.exists():
                        data = json.loads(p.read_text(encoding="utf-8"))
                        self.status_updated.emit(data)
                    else:
                        self.connection_lost.emit()
                except Exception:
                    self.connection_lost.emit()
            self.msleep(3000)

    def stop(self):
        self._running = False
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
        self.resize(1000, 750)
        self.setMinimumSize(800, 600)
        self.setStyleSheet(DARK_THEME)
        self._build_ui()

        # Start background IPC worker
        self._worker = IpcWorker(self.settings.status_path, self)
        self._worker.status_updated.connect(self._on_status)
        self._worker.connection_lost.connect(self._on_daemon_gone)
        self._worker.start()

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
            ("mode",           "Current Mode",          0, 0),
            ("panic_mode",     "Panic Active",          0, 2),
            ("vpn_provider",   "VPN Provider",          1, 0),
            ("vpn_iface",      "Tunnel Interface",      1, 2),
            ("firewall_active","Firewall Active",        2, 0),
            ("route_probe",    "Route Probe Iface",     2, 2),
            ("physical_ifaces","Physical Interfaces",   3, 0),
            ("dns_servers",    "DNS Servers",           3, 2),
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

        root.addWidget(status_box)

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

        ctrl_layout.addWidget(self.btn_panic)
        ctrl_layout.addWidget(self.btn_disable_panic)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(self.btn_unlock)
        root.addWidget(ctrl_box)

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
        root.addWidget(cfg_box)

        # ── Activity Log ──────────────────────────────────────────
        log_box = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_box)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)
        log_layout.addWidget(self.log)
        root.addWidget(log_box)
        root.setStretch(4, 1)  # log expands

    # ------------------------------------------------------------------
    # Status update
    # ------------------------------------------------------------------
    def _on_status(self, data: dict) -> None:
        raw_mode = data.get("mode", "unknown")
        label, color = _MODE_COLORS.get(raw_mode, (raw_mode.upper(), "#8b949e"))
        self.badge.setText(label)
        self.badge.setStyleSheet(f"color: {color}; border-color: {color};")

        self._s["mode"].setText(raw_mode.upper())
        self._s["mode"].setStyleSheet(f"color: {color}; font-weight: 700;")

        panic = data.get("panic_mode", False)
        self._s["panic_mode"].setText("🔴 YES" if panic else "🟢 NO")
        self._s["panic_mode"].setStyleSheet(
            "color: #f85149; font-weight: 700;" if panic else "color: #3fb950; font-weight: 700;"
        )

        self._s["vpn_provider"].setText(
            str(data.get("vpn_provider", "unknown")).upper()
        )
        self._s["vpn_iface"].setText(data.get("vpn_iface") or "— none —")

        fw = data.get("firewall_active", False)
        self._s["firewall_active"].setText("🟢 ACTIVE" if fw else "🔴 INACTIVE")
        self._s["firewall_active"].setStyleSheet(
            "color: #3fb950; font-weight: 700;" if fw else "color: #f85149; font-weight: 700;"
        )

        self._s["route_probe"].setText(data.get("route_probe_iface") or "—")
        self._s["physical_ifaces"].setText(
            ", ".join(data.get("physical_ifaces", [])) or "—"
        )
        self._s["dns_servers"].setText(
            ", ".join(data.get("dns_servers", [])) or "—"
        )

    def _on_daemon_gone(self) -> None:
        self.badge.setText("DAEMON OFFLINE")
        self.badge.setStyleSheet("color: #8b949e; border-color: #30363d;")
        self._log("⚠ Daemon is unreachable — status file not found either.")

    # ------------------------------------------------------------------
    # Privileged actions via IPC (using pkexec ghostctl)
    # ------------------------------------------------------------------
    # Hardcoded trusted paths for ghostctl — prevents PATH injection (LOW-01)
    _GHOSTCTL_CANDIDATES = (
        "/opt/ghosttunnel/venv/bin/ghostctl",
        "/usr/local/bin/ghostctl",
        "/usr/bin/ghostctl",
    )
    # Allowlist of subcommands the GUI is allowed to invoke (injection prevention)
    _ALLOWED_SUBCOMMANDS = frozenset({"panic", "panic-disable", "unlock-network"})

    def _run_privileged(self, subcommand: str) -> bool:
        """Run 'ghostctl <subcommand>' via pkexec for privilege escalation."""
        # SEC-GUI-01: Validate subcommand against allowlist before use
        if subcommand not in self._ALLOWED_SUBCOMMANDS:
            self._log(f"✗ Internal error: unknown subcommand {subcommand!r}")
            return False

        # SEC-GUI-02: Use hardcoded paths instead of shutil.which to prevent PATH hijacking
        ghostctl: str | None = None
        for candidate in self._GHOSTCTL_CANDIDATES:
            if Path(candidate).is_file():
                ghostctl = candidate
                break

        if ghostctl is None:
            self._log("✗ ghostctl not found in any known installation path.")
            QMessageBox.critical(
                self, "Not Found",
                "ghostctl binary not found.\n"
                f"Searched: {', '.join(self._GHOSTCTL_CANDIDATES)}"
            )
            return False

        pkexec = "/usr/bin/pkexec"  # Use absolute path for pkexec too
        if Path(pkexec).is_file():
            args = [pkexec, ghostctl, subcommand]
        else:
            # Fallback: try direct (works if already root)
            args = [ghostctl, subcommand]

        self._log(f"→ Executing: ghostctl {subcommand}")
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, check=False, timeout=15
            )
            output = result.stdout.strip() or result.stderr.strip()
            if result.returncode != 0:
                self._log(f"✗ Error: {output or f'command failed (rc={result.returncode})'}")
                QMessageBox.critical(self, "Command Failed", output or "Unknown error.")
                return False
            self._log(f"✓ {output or 'OK'}")
            return True
        except subprocess.TimeoutExpired:
            self._log("✗ Command timed out after 15s.")
            return False
        except FileNotFoundError:
            self._log(f"✗ Execution failed — binary not found: {ghostctl}")
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
    # Config save
    # ------------------------------------------------------------------
    def _save_config(self) -> None:
        self.settings.allow_lan = self.chk_allow_lan.isChecked()
        self.settings.allow_forwarding = self.chk_allow_fwd.isChecked()
        self.settings.stealth_mode = self.chk_stealth.isChecked()
        self.settings.trust_local_dns = self.chk_trust_dns.isChecked()
        self.settings.ipv6_block = self.chk_ipv6.isChecked()
        self.settings.auto_rotate = self.chk_auto_rotate.isChecked()

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
        except Exception as exc:
            self._log(f"✗ Save failed: {exc}")
            QMessageBox.critical(self, "Save Failed", str(exc))

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
        self._worker.stop()
        super().closeEvent(event)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("GhostTunnel")
    app.setStyle("Fusion")

    settings = Settings.load()
    window = MainWindow(settings)
    window.show()
    sys.exit(app.exec())
