import os
import re

base_dir = r"c:\Users\resan\OneDrive\Documents\16-05-26\Projects\Development\killswitchbe"

def run_refactor():
    print("Starting refactor...")

    # 1. IPC.PY
    ipc_path = os.path.join(base_dir, "src", "ghosttunnel", "core", "ipc.py")
    with open(ipc_path, 'r', encoding='utf-8') as f:
        ipc = f.read()
    
    # We will replace the entire file content for ipc.py as it is thoroughly rewritten for Phase 2 & 3.
    new_ipc = '''from __future__ import annotations

import json
import logging
import os
import socket
import struct
import threading
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

CTRL_SOCKET_PATH = "/run/ghosttunnel/ctrl.sock"
STATUS_SOCKET_PATH = "/run/ghosttunnel/status.sock"
_RECV_LIMIT = 4096
_CLIENT_TIMEOUT = 5.0
_MAX_CHUNKS = 64

class IpcServer:
    def __init__(self, handlers: dict[str, Callable[[], dict]]) -> None:
        self.handlers = handlers
        self._ctrl_sock: socket.socket | None = None
        self._status_sock: socket.socket | None = None
        self._running = False
        self._status_clients: list[socket.socket] = []
        self._status_lock = threading.Lock()

    def start(self) -> None:
        import grp
        try:
            gid = grp.getgrnam("ghosttunnel").gr_gid
        except KeyError:
            logger.warning("Group 'ghosttunnel' not found. Using root GID.")
            gid = 0

        def bind_sock(path_str: str, perms: int) -> socket.socket:
            p = Path(path_str)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists(): p.unlink()
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(path_str)
            os.chmod(path_str, perms)
            try:
                os.chown(path_str, -1, gid)
            except OSError:
                pass
            s.listen(5)
            s.settimeout(1.0)
            return s

        self._ctrl_sock = bind_sock(CTRL_SOCKET_PATH, 0o660)
        self._status_sock = bind_sock(STATUS_SOCKET_PATH, 0o664)

        self._running = True
        threading.Thread(target=self._serve_ctrl, daemon=True, name="ipc-ctrl").start()
        threading.Thread(target=self._serve_status, daemon=True, name="ipc-status").start()
        logger.info("IPC server listening. Ctrl: %s | Status: %s", CTRL_SOCKET_PATH, STATUS_SOCKET_PATH)

    def stop(self) -> None:
        self._running = False
        for s in (self._ctrl_sock, self._status_sock):
            if s:
                try: s.close()
                except OSError: pass
        Path(CTRL_SOCKET_PATH).unlink(missing_ok=True)
        Path(STATUS_SOCKET_PATH).unlink(missing_ok=True)

    def broadcast(self, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8") + b"\\n"
        with self._status_lock:
            dead = []
            for c in self._status_clients:
                try:
                    c.sendall(payload)
                except OSError:
                    dead.append(c)
            for c in dead:
                self._status_clients.remove(c)
                try: c.close()
                except OSError: pass

    def _serve_status(self) -> None:
        while self._running and self._status_sock:
            try:
                conn, _ = self._status_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._status_lock:
                self._status_clients.append(conn)

    def _serve_ctrl(self) -> None:
        while self._running and self._ctrl_sock:
            try:
                conn, _ = self._ctrl_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_ctrl, args=(conn,), daemon=True).start()

    @staticmethod
    def _check_peer_gid(conn: socket.socket) -> bool:
        try:
            import grp
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, peer_uid, peer_gid = struct.unpack("3i", cred)
            if peer_uid == 0:
                return True
            gt_gid = grp.getgrnam("ghosttunnel").gr_gid
            return peer_gid == gt_gid
        except Exception:
            return False

    def _handle_ctrl(self, conn: socket.socket) -> None:
        try:
            with conn:
                conn.settimeout(_CLIENT_TIMEOUT)
                if not self._check_peer_gid(conn):
                    self._send(conn, {"ok": False, "error": "unauthorized: ghosttunnel group required"})
                    return
                raw = self._recv_line(conn)
                if not raw:
                    self._send(conn, {"ok": False, "error": "empty request"})
                    return
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    self._send(conn, {"ok": False, "error": "invalid JSON"})
                    return

                action = str(msg.get("action", ""))
                handler = self.handlers.get(action)
                if not handler:
                    self._send(conn, {"ok": False, "error": f"unknown action: {action}"})
                    return

                try:
                    result = handler()
                    self._send(conn, {"ok": True, **(result or {})})
                except Exception as exc:
                    self._send(conn, {"ok": False, "error": "internal handler error"})
        except Exception:
            pass

    @staticmethod
    def _recv_line(conn: socket.socket) -> str | None:
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            try:
                chunk = conn.recv(min(256, _RECV_LIMIT - len(buf)))
            except OSError: break
            if not chunk: break
            buf += chunk
            chunks += 1
            if b"\\n" in buf: break
        text = buf.decode("utf-8", errors="replace").strip()
        return text if text else None

    @staticmethod
    def _send(conn: socket.socket, data: dict) -> None:
        try:
            conn.sendall(json.dumps(data).encode("utf-8") + b"\\n")
        except OSError:
            pass

def send_command(action: str, timeout: float = 5.0) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(CTRL_SOCKET_PATH)
        except FileNotFoundError:
            raise ConnectionRefusedError("GhostTunnel daemon is not running.")
        payload = {"action": action, "payload": {}, "token": ""}
        s.sendall(json.dumps(payload).encode("utf-8") + b"\\n")
        buf = b""
        chunks = 0
        while len(buf) < _RECV_LIMIT and chunks < _MAX_CHUNKS:
            try: chunk = s.recv(256)
            except OSError: break
            if not chunk: break
            buf += chunk
            chunks += 1
            if b"\\n" in buf: break
    raw = buf.decode("utf-8", errors="replace").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConnectionRefusedError(f"Daemon returned malformed response.") from exc
'''
    with open(ipc_path, 'w', encoding='utf-8') as f:
        f.write(new_ipc)
    print("Updated ipc.py")

    # 2. GUI MAIN.PY
    gui_path = os.path.join(base_dir, "src", "ghosttunnel", "gui", "main.py")
    with open(gui_path, 'r', encoding='utf-8') as f:
        gui = f.read()

    # Replace _run_privileged to remove pkexec
    gui = re.sub(
        r'    def _run_privileged\(self, subcommand: str\) -> bool:.*?            return False',
        '''    def _run_privileged(self, subcommand: str) -> bool:
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
            return False''',
        gui, flags=re.DOTALL
    )

    # Replace IpcWorker to be event-driven
    gui = re.sub(
        r'    def run\(self\):.*?            self\._wake\.clear\(\)',
        '''    def run(self):
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
                self._wake.clear()''',
        gui, flags=re.DOTALL
    )
    with open(gui_path, 'w', encoding='utf-8') as f:
        f.write(gui)
    print("Updated gui/main.py")

    # 3. DAEMON.PY
    daemon_path = os.path.join(base_dir, "src", "ghosttunnel", "daemon.py")
    with open(daemon_path, 'r', encoding='utf-8') as f:
        daemon = f.read()

    new_ipc_handlers = """    def _ipc_unlock_network(self) -> dict:
        import threading
        def _stop():
            import time
            time.sleep(0.5)
            from ghosttunnel.core.emergency import PANIC_LOCK_PATH
            Path(PANIC_LOCK_PATH).unlink(missing_ok=True)
            self.firewall.deactivate()
            self._running = False
        threading.Thread(target=_stop).start()
        return {"message": "Network unlocked. Daemon stopping."}"""

    daemon = daemon.replace("        return {\"mode\": \"unknown\", \"message\": \"No sync has completed yet.\"}", 
                          "        return {\"mode\": \"unknown\", \"message\": \"No sync has completed yet.\"}\n\n" + new_ipc_handlers)

    daemon = daemon.replace(
        '''        self._ipc = IpcServer({
            "panic": self._ipc_panic,
            "panic-disable": self._ipc_panic_disable,
            "status": self._ipc_status,
        })''',
        '''        self._ipc = IpcServer({
            "panic": self._ipc_panic,
            "panic-disable": self._ipc_panic_disable,
            "status": self._ipc_status,
            "unlock-network": self._ipc_unlock_network,
        })'''
    )

    daemon = daemon.replace(
        '''            self._write_status_file(state)
            self._last_state = state
            return state''',
        '''            self._write_status_file(state)
            self._last_state = state
            if signature != self._last_signature and self._ipc:
                import time
                self._ipc.broadcast({"event": "status_change", "state": asdict(state), "timestamp": time.time()})
            return state'''
    )
    with open(daemon_path, 'w', encoding='utf-8') as f:
        f.write(daemon)
    print("Updated daemon.py")

    # 4. FIREWALL.PY
    fw_path = os.path.join(base_dir, "src", "ghosttunnel", "core", "firewall.py")
    with open(fw_path, 'r', encoding='utf-8') as f:
        fw = f.read()

    # Add EXTERNAL_KS_ACTIVE check
    fw = re.sub(
        r'    def __init__\(self, settings: Settings\) -> None:.*?        self\.table_ref = f"inet \{self\.settings\.table_name\}"',
        '''    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.table_ref = f"inet {self.settings.table_name}"
        self.external_ks_active = False
        try:
            res = run([self.nft, "list", "chains"], check=False)
            if "PVPN" in res.stdout or "pvpn" in res.stdout or "pvpn-killswitch" in res.stdout:
                self.external_ks_active = True
                logger.info("External killswitch detected. GhostTunnel will use isolated chain GHOSTTUNNEL_KS.")
        except Exception:
            pass''',
        fw, flags=re.DOTALL
    )

    # Modify deactivate
    fw = fw.replace(
        '''    def deactivate(self) -> None:
        require_root()
        run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)''',
        '''    def deactivate(self) -> None:
        require_root()
        if self.external_ks_active:
            run([self.nft, "delete", "chain", "inet", "filter", "GHOSTTUNNEL_KS"], check=False)
        else:
            run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)'''
    )

    # Modify activate
    fw = fw.replace(
        '''    def activate(self, plan: FirewallPlan) -> None:
        if not plan.ruleset:
            logger.warning("activate() called with empty ruleset — skipping to avoid open firewall.")
            return
        require_root()
        # Delete existing table first so re-apply is idempotent
        run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)
        result = run([self.nft, "-f", "-"], input_text=plan.ruleset, check=False)''',
        '''    def activate(self, plan: FirewallPlan) -> None:
        if not plan.ruleset:
            return
        require_root()
        if self.external_ks_active:
            self.deactivate()
        else:
            run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)
        result = run([self.nft, "-f", "-"], input_text=plan.ruleset, check=False)'''
    )

    # Modify render_panic
    fw = fw.replace(
        '''    def _render_panic_rules(self) -> str:
        """Strict FAIL CLOSED ruleset. Blocks everything except loopback."""
        table = self.settings.table_name
        return f"""
table inet {table} {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    limit rate 10/second log prefix "VPN-PANIC-DROP-IN: " level warn
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state established,related accept
    limit rate 10/second log prefix "VPN-PANIC-DROP-OUT: " level warn
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
}
"""''',
        '''    def _render_panic_rules(self) -> str:
        if self.external_ks_active:
            return """
table inet filter {
  chain GHOSTTUNNEL_KS {
    type filter hook output priority -10;
    oifname "lo" accept
    ct state established,related accept
    drop
  }
}
"""
        table = self.settings.table_name
        return f"""
table inet {table} {{
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }}
  chain output {{
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state established,related accept
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
  }}
}}
"""'''
    )

    # Modify render_rules to change table/chains if external_ks_active is true.
    # To keep it simple, we replace the first line of _render_rules.
    fw = fw.replace(
        '''        table = self.settings.table_name
        lines: list[str] = [f"table inet {table} {{"]''',
        '''        if self.external_ks_active:
            # When external KS is active, inject into standard filter table 
            # and append rules as GHOSTTUNNEL_KS chain drops/accepts.
            lines = ["table inet filter {"]
        else:
            table = self.settings.table_name
            lines = [f"table inet {table} {{"]'''
    )
    # Change "chain input {" to "chain input {" or "chain GHOSTTUNNEL_KS {"
    fw = fw.replace(
        '''        # -- INPUT CHAIN --
        lines.append("  chain input {")
        lines.append("    type filter hook input priority filter; policy drop;")''',
        '''        # -- INPUT CHAIN --
        if self.external_ks_active:
            lines.append("  chain GHOSTTUNNEL_KS_IN {")
            lines.append("    type filter hook input priority -10;")
        else:
            lines.append("  chain input {")
            lines.append("    type filter hook input priority filter; policy drop;")'''
    )
    fw = fw.replace(
        '''        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-In: " level warn')
        lines.append("  }")''',
        '''        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-In: " level warn')
        if self.external_ks_active:
            lines.append("    drop")
        lines.append("  }")'''
    )
    # Output chain
    fw = fw.replace(
        '''        # -- OUTPUT CHAIN --
        lines.append("  chain output {")
        lines.append("    type filter hook output priority filter; policy drop;")''',
        '''        # -- OUTPUT CHAIN --
        if self.external_ks_active:
            lines.append("  chain GHOSTTUNNEL_KS_OUT {")
            lines.append("    type filter hook output priority -10;")
        else:
            lines.append("  chain output {")
            lines.append("    type filter hook output priority filter; policy drop;")'''
    )
    fw = fw.replace(
        '''        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-Out: " level warn')
        lines.append("  }")''',
        '''        lines.append('    limit rate 10/second log prefix "VPN-KillSwitch-Out: " level warn')
        if self.external_ks_active:
            lines.append("    drop")
        lines.append("  }")'''
    )
    # Forward chain
    fw = fw.replace(
        '''        # -- FORWARD CHAIN (MED-08: restricted direction) --
        lines.append("  chain forward {")
        lines.append("    type filter hook forward priority filter; policy drop;")''',
        '''        # -- FORWARD CHAIN (MED-08: restricted direction) --
        if self.external_ks_active:
            lines.append("  chain GHOSTTUNNEL_KS_FWD {")
            lines.append("    type filter hook forward priority -10;")
        else:
            lines.append("  chain forward {")
            lines.append("    type filter hook forward priority filter; policy drop;")'''
    )
    fw = fw.replace(
        '''        lines.append("    ct state invalid drop")
        lines.append("  }")''',
        '''        lines.append("    ct state invalid drop")
        if self.external_ks_active:
            lines.append("    drop")
        lines.append("  }")'''
    )
    
    with open(fw_path, 'w', encoding='utf-8') as f:
        f.write(fw)
    print("Updated firewall.py")

    # 5. INSTALL.SH
    install_path = os.path.join(base_dir, "install.sh")
    with open(install_path, 'r', encoding='utf-8') as f:
        install = f.read()

    install = install.replace(
        "# 4. Setup Systemd daemon\necho \"[*] Configuring Security Daemon in Systemd...\"",
        """# 4. Setup Systemd daemon
echo "[*] Creating ghosttunnel group for IPC access..."
groupadd -f ghosttunnel
if [ -n "${SUDO_USER:-}" ]; then
  usermod -aG ghosttunnel "$SUDO_USER" || true
fi

echo "[*] Configuring Security Daemon in Systemd...\""""
    )
    with open(install_path, 'w', encoding='utf-8') as f:
        f.write(install)
    print("Updated install.sh")

run_refactor()
