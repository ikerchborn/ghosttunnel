<div align="center">
  <h1>🛡️ GhostTunnel</h1>
  <p><strong>Military-Grade VPN Kill Switch & OPSEC Infrastructure for Linux</strong></p>

  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](./SECURITY.md)
  [![Architecture: V2.0](https://img.shields.io/badge/Architecture-Event--Driven_V2.0-brightgreen.svg)](#)
</div>

---

## 1. Overview

**GhostTunnel** is an enterprise-grade, daemonized OPSEC (Operations Security) infrastructure specifically engineered to enforce a strict **FAIL-CLOSED** firewall posture. 

If your VPN drops, GhostTunnel guarantees that absolutely zero unencrypted packets will leave your machine. By using atomic `nftables` transactions, it secures your network before your operating system even finishes booting and responds dynamically to network changes.

This architecture prioritizes **Privacy over Connectivity, always.** It provides an impenetrable shield around your internet traffic, eliminating the 1-3 second window of vulnerability present in traditional reactive kill switches.

---

## 2. Requirements

GhostTunnel is designed exclusively for **Debian-based Linux systems** (Debian, Ubuntu, Kali, ParrotOS). 

**System Dependencies:**
- `nftables` (Core firewall engine)
- `systemd` (Daemon management and pre-boot initialization)
- `python3` (Python 3.12+ recommended)
- `python3-pyqt6` (For the GUI)

---

## 3. Installation

GhostTunnel must be installed via the provided bash script, which configures the systemd service, installs dependencies, and creates the required UNIX groups for secure local access.

```bash
git clone https://github.com/ikerchborn/ghosttunnel.git
cd ghosttunnel
chmod +x install.sh
sudo ./install.sh
```

> [!WARNING]
> **Mandatory Session Restart:**
> The installer automatically creates a `ghosttunnel` group and adds your current user to it. **You must log out and log in again** for these group permissions to take effect before using the GUI or CLI.

---

## 4. Architecture

GhostTunnel relies on a highly secure **Event-Driven IPC (Inter-Process Communication)** model, splitting operations into a privileged backend and an unprivileged frontend.

### The Two-Socket Model
Instead of relying on legacy polling or risky privilege escalation, GhostTunnel uses two dedicated Unix Domain Sockets located in `/run/ghosttunnel/`:
1. **`ctrl.sock` (Control):** A blocking request/response socket used to send commands to the daemon.
   - **Permissions:** `0o660` (Root + `ghosttunnel` group).
   - **Format:** `{"action": "<name>", "payload": {}}`
2. **`status.sock` (Status):** A continuous pub/sub stream where the daemon broadcasts state changes instantly.
   - **Permissions:** `0o664` (Root + `ghosttunnel` group).
   - **Format:** `{"event": "status_change", "state": "<state_dict>", "timestamp": <unix_ts>}`

### Privilege Model
- **Daemon (`ghostd`):** Runs as `root` via systemd. It handles all raw `nftables` manipulation, routing analysis, and network interface reading.
- **GUI (`ghostgui`):** Runs entirely in user-space as your standard user. Because your user is in the `ghosttunnel` group, it authenticates to the sockets securely via kernel-level `SO_PEERCRED` group-ID validation.

---

## 5. Usage

### Starting the Engine
GhostTunnel **does not start automatically** upon installation to prevent locking you out while configuring your VPN.
```bash
sudo systemctl start ghosttunnel
sudo systemctl enable ghosttunnel
```

### Graphical User Interface (GUI)
Launch the control panel from your desktop application launcher or via terminal:
```bash
ghostgui
```
The GUI connects directly to the daemon's event socket, providing real-time telemetry, a live activity log, and one-click controls for **PANIC**, **Disable Panic**, and **Emergency Unlock**.

### Command Line Interface (`ghostctl`)
The `ghostctl` binary interacts with the daemon's control socket:
- `ghostctl status`: Show current protection status.
- `ghostctl panic`: Instantly cut off the entire network.
- `ghostctl panic-disable`: Restore normal operation.
- `ghostctl unlock-network`: Emergency stop the daemon and flush rules.

*(Note: While CLI commands previously required `sudo`, any user in the `ghosttunnel` group can now execute them).*

---

## 6. Pre-Push Security Pipeline

GhostTunnel enforces code integrity via autonomous AI subagents. Before any commit is pushed to the repository, a strict verification pipeline executes:

When a developer runs `verify and push`, the following autonomous agents are triggered:
- **`security_auditor`:** Scans for SQLi, XSS, insecure dependencies, path traversals, hardcoded secrets, and unsafe deserialization.
- **`qa_engineer`:** Enforces linting, unit tests, and structural validation.

Only if both subagents return a clean bill of health will the `git push` command be authorized.

---

## 7. Killswitch Compatibility

GhostTunnel is engineered to coexist peacefully with commercial VPNs like **ProtonVPN** that use their own internal killswitches.

- **Non-Destructive Operations:** The daemon actively scans for existing VPN rules (e.g., ProtonVPN's `pvpn-killswitch` chains). 
- **Isolated Chain Injection:** If external chains are detected, GhostTunnel abandons its private table and injects its own high-priority isolated chains (`GHOSTTUNNEL_KS_IN`, `_OUT`, `_FWD`) directly into the standard `inet filter` table.
- **Idempotence:** GhostTunnel never blindly flushes the `inet` table. On daemon stop, or when executing `ghost-recover.sh`, it exclusively deletes the `GHOSTTUNNEL_KS_*` chains, ensuring that ProtonVPN's native security layer is left completely intact.

---

## 8. Security Model

- **No `pkexec` or `sudo` at Runtime:** The GUI has been stripped of all privilege escalation mechanisms. It operates 100% via the secure Unix socket.
- **Kernel-Level Authentication:** Socket requests are authenticated by the Linux kernel using `SO_PEERCRED` to verify the sender's GID matches the `ghosttunnel` group.
- **Zero Shell Injection:** A strict static audit confirms zero usage of `shell=True`, `eval`, or unescaped `subprocess` commands across the entire codebase.

---

## 9. Development & Verification

### Dev Environment
GhostTunnel relies heavily on Linux-native kernel mechanics (`nftables`, `systemd`, `AF_UNIX` sockets). If developing on **Windows**, a WSL (Windows Subsystem for Linux) environment is strictly required to execute or test the daemon natively.

### Static Verification Suite
To verify the integrity of the architecture and ensure no regressions occur during development, run the following 8 static assertions:

```bash
# 1. No privilege escalation tools left behind
grep -rn "pkexec" src/

# 2. No polling loops in the GUI (watchdogs only)
grep -rn "time.sleep" src/

# 3. No shell injection vectors
grep -rn "shell=True" src/

# 4. No destructive rule flushes
grep -rn "nft flush" src/

# 5. Full table deletion restricted to recovery scripts
grep -rn "nft delete table inet ghosttunnel" src/

# 6. Socket Auth verified
grep -rn "SO_PEERCRED\|GID\|getgroups" src/core/ipc.py

# 7. Dual sockets present
grep -rn "status.sock\|ctrl.sock" src/

# 8. Isolated chain integration
grep -rn "GHOSTTUNNEL_KS" src/core/firewall.py
```
