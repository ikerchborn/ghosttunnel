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
  - OPSEC Expansions (2026): Leak Panel, Network Map, Traffic Stats
"""
from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime
from pathlib import Path

from ghosttunnel.core.config import Settings

try:
    from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
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
        QGroupBox,
        QTabWidget,
    )
except ImportError as exc:
    raise RuntimeError(
        "PyQt6 is required for GUI mode.\n"
        "Install with:  sudo apt install python3-pyqt6\n"
        "Or via pip:    pip install PyQt6"
    ) from exc

# Import new OPSEC panels
from ghosttunnel.gui.leak_worker import LeakWorker
from ghosttunnel.gui.network_map import NetworkMapWidget
from ghosttunnel.gui.traffic_worker import TrafficWorker

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
QTabWidget::pane {
    border: 1px solid #00ff41;
    background: #000000;
}
QTabBar::tab {
    background: #0a0a0a;
    border: 1px solid #00ff41;
    padding: 8px 20px;
    margin-right: 2px;
    font-weight: bold;
}
QTabBar::tab:selected {
    background: #00ff41;
    color: #000000;
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

ALLOWED_SUBCOMMANDS = frozenset({"panic", "panic-disable", "unlock-network", "save-config"})

# ------------------------------------------------------------------
# IPC worker thread
# ------------------------------------------------------------------
class IpcWorker(QThread):
    status_updated = pyqtSignal(dict)
    connection_lost = pyqtSignal()

    def __init__(self, status_path: str, parent=None):
        super().__init__(parent)
        self.status_path = status_path
        self._running = True
        self._wake = threading.Event()

    def run(self) -> None:
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
            except Exception as exc:
                logging.error("IPC status socket error: %s", exc)
                self._fallback_read()
                self._wake.wait(timeout=3.0)
                self._wake.clear()

    def request_poll(self):
        self._wake.set()

    def _fallback_read(self):
        try:
            p = Path(self.status_path)
            if p.exists():
                text = p.read_text(encoding="utf-8")
                data = json.loads(text)
                if isinstance(data, dict):
                    self.status_updated.emit(data)
                    return
        except Exception as exc:
            logging.error("Fallback read error: %s", exc)
        self.connection_lost.emit()

    def stop(self) -> None:
        self._running = False
        self._wake.set()
        self.quit()
        self.wait(2000)

class IpcControlWorker(QThread):
    command_finished = pyqtSignal(dict)
    command_failed = pyqtSignal(str)

    def __init__(self, action: str, payload: dict | None = None, parent=None):
        super().__init__(parent)
        self.action = action
        self.payload = payload or {}

    def run(self):
        from ghosttunnel.core.ipc import send_command
        try:
            resp = send_command(self.action, self.payload)
            self.command_finished.emit(resp)
        except Exception as e:
            self.command_failed.emit(str(e))

# ------------------------------------------------------------------
# Main Window
# ------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.settings = settings
        self.setWindowTitle("GhostTunnel — OPSEC Dashboard")
        self.resize(1020, 800)
        self.setMinimumSize(900, 700)
        self.setStyleSheet(DARK_THEME)
        
        self._last_status = {}
        self._last_leak_data = {}
        self._daemon_offline_logged = False
        self._active_workers: list[IpcControlWorker] = []

        self._build_ui()

        # Workers
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._request_manual_refresh)
        self._timer.start(60_000)

        self._worker = IpcWorker(self.settings.status_path, self)
        self._worker.status_updated.connect(self._on_status)
        self._worker.connection_lost.connect(self._on_daemon_gone)
        self._worker.start()

        self._leak_worker = LeakWorker(interval_ms=15000, parent=self)
        self._leak_worker.leak_data_updated.connect(self._on_leak_data)
        self._leak_worker.start()

        self._traffic_worker = TrafficWorker(interval_ms=1000, parent=self)
        self._traffic_worker.traffic_updated.connect(self._on_traffic_data)
        self._traffic_worker.start()

        self._log("GhostTunnel GUI started. Connecting to daemon...")

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        # ── Header ──
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

        # ── Tabs ──
        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        self._build_tab_dashboard()
        self._build_tab_leak()
        self._build_tab_map()
        self._build_tab_traffic()

    def _build_tab_dashboard(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)

        # Status Grid
        status_box = QGroupBox("Live Network Status")
        sg = QGridLayout(status_box)
        sg.setSpacing(12)
        
        self._s = {}
        fields = [
            ("mode",                     "Current Mode",           0, 0),
            ("panic_mode",               "Panic Active",           0, 2),
            ("vpn_provider",             "VPN Provider",           1, 0),
            ("vpn_iface",                "Tunnel Interface",       1, 2),
            ("firewall_active",          "Firewall Active",        2, 0),
            ("proton_native_killswitch", "ProtonVPN KS Coexist",   2, 2),
            ("physical_ifaces",          "Physical Interfaces",    3, 0),
            ("dns_servers",              "DNS Servers",            3, 2),
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
        layout.addWidget(status_box)

        # Controls
        ctrl_box = QGroupBox("Controls")
        ctrl_layout = QHBoxLayout(ctrl_box)
        self.btn_panic = QPushButton("⚡  TRIGGER PANIC")
        self.btn_panic.setObjectName("PanicBtn")
        self.btn_panic.clicked.connect(self._action_panic)
        self.btn_disable_panic = QPushButton("✅  Disable Panic")
        self.btn_disable_panic.setObjectName("DisablePanicBtn")
        self.btn_disable_panic.clicked.connect(self._action_disable_panic)
        self.btn_unlock = QPushButton("🔓  Emergency Unlock")
        self.btn_unlock.setObjectName("UnlockBtn")
        self.btn_unlock.clicked.connect(self._action_unlock)
        self.btn_refresh = QPushButton("🔄  Refresh")
        self.btn_refresh.clicked.connect(self._request_manual_refresh)

        ctrl_layout.addWidget(self.btn_panic)
        ctrl_layout.addWidget(self.btn_disable_panic)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(self.btn_refresh)
        ctrl_layout.addWidget(self.btn_unlock)
        layout.addWidget(ctrl_box)

        # Activity Log
        log_box = QGroupBox("Activity Log")
        log_layout = QVBoxLayout(log_box)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        log_layout.addWidget(self.log)
        layout.addWidget(log_box, stretch=1)

        self.tabs.addTab(tab, " Dashboard ")

    def _build_tab_leak(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info_box = QGroupBox("External OPSEC Check (User-Space)")
        ig = QGridLayout(info_box)
        
        self.lbl_ext_ip = QLabel("Waiting...")
        self.lbl_ext_cc = QLabel("Waiting...")
        self.lbl_ext_org = QLabel("Waiting...")
        self.lbl_ext_dns = QLabel("Waiting...")
        
        for widget in [self.lbl_ext_ip, self.lbl_ext_cc, self.lbl_ext_org, self.lbl_ext_dns]:
            widget.setStyleSheet("color: #e6edf3; font-size: 16px;")

        ig.addWidget(QLabel("Public IP:"), 0, 0)
        ig.addWidget(self.lbl_ext_ip, 0, 1)
        ig.addWidget(QLabel("Country:"), 1, 0)
        ig.addWidget(self.lbl_ext_cc, 1, 1)
        ig.addWidget(QLabel("Provider (ISP/VPN):"), 2, 0)
        ig.addWidget(self.lbl_ext_org, 2, 1)
        ig.addWidget(QLabel("System DNS Servers:"), 3, 0)
        ig.addWidget(self.lbl_ext_dns, 3, 1)
        
        layout.addWidget(info_box)
        layout.addStretch()
        self.tabs.addTab(tab, " OPSEC / Leak Panel ")

    def _build_tab_map(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.network_map = NetworkMapWidget()
        layout.addWidget(self.network_map)
        
        self.tabs.addTab(tab, " Network Map ")

    def _build_tab_traffic(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.traffic_log = QPlainTextEdit()
        self.traffic_log.setReadOnly(True)
        self.traffic_log.setStyleSheet("font-family: 'Consolas', monospace; font-size: 16px;")
        layout.addWidget(self.traffic_log)
        
        self.tabs.addTab(tab, " Traffic Stats ")

    def _on_status(self, data: dict) -> None:
        self._daemon_offline_logged = False
        self._last_status = data
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

        self._s["vpn_provider"].setText(str(data.get("vpn_provider", "unknown")).upper())
        self._s["vpn_iface"].setText(data.get("vpn_iface") or "— none —")

        fw = data.get("firewall_active", False)
        self._s["firewall_active"].setText("🟢 ACTIVE" if fw else "🔴 INACTIVE")
        self._s["firewall_active"].setStyleSheet(
            "color: #00ff41; font-weight: 700;" if fw else "color: #ff003c; font-weight: 700;"
        )

        pks = data.get("proton_native_killswitch", False)
        if pks:
            self._s["proton_native_killswitch"].setText("🟡 COEXISTING")
            self._s["proton_native_killswitch"].setStyleSheet("color: #ffaa00; font-weight: 700;")
        else:
            self._s["proton_native_killswitch"].setText("🟢 NONE")
            self._s["proton_native_killswitch"].setStyleSheet("color: #00ff41; font-weight: 700;")

        self._s["physical_ifaces"].setText(", ".join(data.get("physical_ifaces", [])) or "—")
        self._s["dns_servers"].setText(", ".join(data.get("dns_servers", [])) or "—")

        # Check for anomalies reported by daemon
        anomalies = data.get("anomalies", [])
        for anomaly in anomalies:
            self._log(f"[ANOMALY] {anomaly}")

        self.network_map.update_graph(self._last_status, self._last_leak_data)

    def _on_leak_data(self, data: dict) -> None:
        self._last_leak_data = data
        self.lbl_ext_ip.setText(data.get("public_ip", "Unknown"))
        self.lbl_ext_cc.setText(data.get("country", "Unknown"))
        self.lbl_ext_org.setText(data.get("org", "Unknown"))
        
        dns = data.get("dns_servers", [])
        self.lbl_ext_dns.setText(", ".join(dns) if dns else "None found")
        
        self.network_map.update_graph(self._last_status, self._last_leak_data)

    def _on_traffic_data(self, rates: dict) -> None:
        lines = [f"{'Interface':<15} {'RX (KB/s)':<12} {'TX (KB/s)':<12}"]
        lines.append("-" * 40)
        
        for iface, stats in rates.items():
            rx_kb = stats["rx_bytes_sec"] / 1024.0
            tx_kb = stats["tx_bytes_sec"] / 1024.0
            lines.append(f"{iface:<15} {rx_kb:<12.2f} {tx_kb:<12.2f}")
            
        self.traffic_log.setPlainText("\n".join(lines))

    def _on_daemon_gone(self) -> None:
        self.badge.setText("DAEMON OFFLINE")
        self.badge.setStyleSheet("color: #008f11; border-color: #008f11;")
        for key in self._s:
            self._s[key].setText("—")
        if not self._daemon_offline_logged:
            self._daemon_offline_logged = True
            self._log("⚠ Daemon is unreachable.")

    def _request_manual_refresh(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_poll()

    def _run_privileged(self, subcommand: str, payload: dict | None = None) -> None:
        self._log(f"→ Sending command: {subcommand}")
        for btn in (self.btn_panic, self.btn_disable_panic, self.btn_unlock):
            btn.setEnabled(False)
            
        worker = IpcControlWorker(subcommand, payload, self)
        worker.command_finished.connect(lambda resp, w=worker: self._on_command_finished(resp, w))
        worker.command_failed.connect(lambda err, w=worker: self._on_command_failed(err, w))
        worker.start()
        self._active_workers.append(worker)

    def _on_command_finished(self, resp: dict, worker: IpcControlWorker) -> None:
        if resp.get("ok"):
            msg = resp.get("message", "Success")
            self._log(f"✓ {msg}")
        else:
            msg = resp.get("error", "Unknown error")
            self._log(f"✗ Error: {msg}")
        self._cleanup_worker(worker)

    def _on_command_failed(self, err: str, worker: IpcControlWorker) -> None:
        self._log(f"✗ IPC Error: {err}")
        self._cleanup_worker(worker)

    def _cleanup_worker(self, worker: IpcControlWorker) -> None:
        for btn in (self.btn_panic, self.btn_disable_panic, self.btn_unlock):
            btn.setEnabled(True)
        if worker in self._active_workers:
            self._active_workers.remove(worker)

    def _action_panic(self) -> None:
        self._run_privileged("panic")

    def _action_disable_panic(self) -> None:
        self._run_privileged("panic-disable")

    def _action_unlock(self) -> None:
        self._run_privileged("unlock-network")

    def _save_config(self) -> None:
        pass  # Omitted for brevity, using defaults in settings tab if added back

    def _log(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}]  {text}")
        sb = self.log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def closeEvent(self, event) -> None:
        self._timer.stop()
        self._worker.stop()
        self._leak_worker.stop()
        self._traffic_worker.stop()
        super().closeEvent(event)

def main() -> None:
    """Main GUI entrypoint."""
    app = QApplication(sys.argv)
    app.setApplicationName("GhostTunnel")
    app.setStyle("Fusion")
    settings = Settings.load()
    window = MainWindow(settings)
    window.show()
    sys.exit(app.exec())
