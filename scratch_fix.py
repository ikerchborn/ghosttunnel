import os
import re

base_dir = r"c:\Users\resan\OneDrive\Documents\16-05-26\Projects\Development\killswitchbe"

def run_fix():
    # 1. Clean gui/main.py pkexec comments
    gui_path = os.path.join(base_dir, "src", "ghosttunnel", "gui", "main.py")
    with open(gui_path, 'r', encoding='utf-8') as f:
        gui = f.read()

    gui = gui.replace("Privilege escalation via pkexec for all root commands", "Privilege escalation via IPC for all root commands")
    gui = gui.replace("_run_privileged now falls back gracefully if pkexec not available", "_run_privileged now falls back gracefully via IPC")
    gui = gui.replace("Save config works even when running as non-root (pkexec escalation)", "Save config works via IPC")
    gui = gui.replace("Obsolete policykit-1 reference replaced with polkitd/pkexec", "Obsolete policykit-1 reference removed")
    gui = gui.replace("Privileged actions via IPC (using pkexec ghostctl)", "Privileged actions via IPC (direct to socket)")
    gui = gui.replace("Use pkexec for writing to /etc/", "Requires root for writing to /etc/")

    # Fix Case 1 & 3: IpcWorker exponential backoff and reconnection logic
    old_ipc_worker_run = """    def run(self):
        import socket, json
        from ghosttunnel.core.ipc import STATUS_SOCKET_PATH
        while self._running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(10.0) # Watchdog
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
                self._wake.clear()"""

    new_ipc_worker_run = """    def run(self):
        import socket, json
        from ghosttunnel.core.ipc import STATUS_SOCKET_PATH
        retry_delays = [1.0, 2.0, 4.0, 8.0, 16.0]
        retry_idx = 0
        while self._running:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(10.0) # Watchdog
                    s.connect(STATUS_SOCKET_PATH)
                    retry_idx = 0  # Connected successfully, reset backoff
                    while self._running:
                        f = s.makefile('r', encoding='utf-8')
                        line = f.readline()
                        if not line:
                            # EOF received, daemon probably restarted
                            raise ConnectionAbortedError("EOF from status.sock")
                        data = json.loads(line)
                        if data.get("event") == "status_change":
                            state = data.get("state", {})
                            self.status_updated.emit(state)
            except Exception as e:
                # Disconnected or failed to connect
                self._fallback_read()
                delay = retry_delays[min(retry_idx, len(retry_delays)-1)]
                retry_idx += 1
                self._wake.wait(timeout=delay)
                self._wake.clear()"""

    gui = gui.replace(old_ipc_worker_run, new_ipc_worker_run)
    with open(gui_path, 'w', encoding='utf-8') as f:
        f.write(gui)

    # 2. Fix Case 2: install.sh warning
    install_path = os.path.join(base_dir, "install.sh")
    with open(install_path, 'r', encoding='utf-8') as f:
        install = f.read()

    install = install.replace("if [ -n \"${SUDO_USER:-}\" ]; then\n  usermod -aG ghosttunnel \"$SUDO_USER\" || true\nfi",
                              "if [ -n \"${SUDO_USER:-}\" ]; then\n  usermod -aG ghosttunnel \"$SUDO_USER\" || true\n  echo \"[!] IMPORTANT: You must log out and log in again for group permissions to take effect.\"\nfi")
    with open(install_path, 'w', encoding='utf-8') as f:
        f.write(install)

    # 3. Fix Case 4: firewall.py chains
    fw_path = os.path.join(base_dir, "src", "ghosttunnel", "core", "firewall.py")
    with open(fw_path, 'r', encoding='utf-8') as f:
        fw = f.read()

    old_deact = """    def deactivate(self) -> None:
        require_root()
        if self.external_ks_active:
            run([self.nft, "delete", "chain", "inet", "filter", "GHOSTTUNNEL_KS"], check=False)
        else:
            run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)"""

    new_deact = """    def deactivate(self) -> None:
        require_root()
        if self.external_ks_active:
            run([self.nft, "delete", "chain", "inet", "filter", "GHOSTTUNNEL_KS_IN"], check=False)
            run([self.nft, "delete", "chain", "inet", "filter", "GHOSTTUNNEL_KS_OUT"], check=False)
            run([self.nft, "delete", "chain", "inet", "filter", "GHOSTTUNNEL_KS_FWD"], check=False)
        else:
            run([self.nft, "delete", "table", "inet", self.settings.table_name], check=False)"""
    fw = fw.replace(old_deact, new_deact)

    old_panic = """  chain GHOSTTUNNEL_KS {
    type filter hook output priority -10;
    oifname "lo" accept
    ct state established,related accept
    drop
  }"""
    new_panic = """  chain GHOSTTUNNEL_KS_IN {
    type filter hook input priority -10;
    iifname "lo" accept
    ct state established,related accept
    drop
  }
  chain GHOSTTUNNEL_KS_OUT {
    type filter hook output priority -10;
    oifname "lo" accept
    ct state established,related accept
    drop
  }
  chain GHOSTTUNNEL_KS_FWD {
    type filter hook forward priority -10;
    drop
  }"""
    fw = fw.replace(old_panic, new_panic)

    with open(fw_path, 'w', encoding='utf-8') as f:
        f.write(fw)

    # 4. Fix Case 5: ghost-recover.sh
    rec_path = os.path.join(base_dir, "src", "ghost-recover.sh")
    with open(rec_path, 'r', encoding='utf-8') as f:
        rec = f.read()

    old_rec = """    echo "    nft delete table inet ghosttunnel"
    exit 1
fi

"$nft" delete table inet ghosttunnel 2>/dev/null || true"""
    new_rec = """    echo "    nft delete table inet ghosttunnel (or GHOSTTUNNEL_KS chains)"
    exit 1
fi

"$nft" delete chain inet filter GHOSTTUNNEL_KS_IN 2>/dev/null || true
"$nft" delete chain inet filter GHOSTTUNNEL_KS_OUT 2>/dev/null || true
"$nft" delete chain inet filter GHOSTTUNNEL_KS_FWD 2>/dev/null || true
"$nft" delete table inet ghosttunnel 2>/dev/null || true"""
    rec = rec.replace(old_rec, new_rec)
    with open(rec_path, 'w', encoding='utf-8') as f:
        f.write(rec)

    print("Fix applied successfully.")

run_fix()
