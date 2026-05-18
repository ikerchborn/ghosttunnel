<div align="center">
  <h1>🛡️ GhostTunnel</h1>
  <p><strong>VPN Kill Switch & OPSEC Infrastructure for Linux</strong></p>

  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](./SECURITY.md)
  [![Security: Atomic](https://img.shields.io/badge/Security-Atomic_Nftables-red.svg)](#fail-closed-architecture)
</div>

---

GhostTunnel is an advanced security daemon for Linux systems designed to act as the ultimate safety net for your privacy. It implements a **FAIL-CLOSED** architecture using atomic `nftables` rules that ensure absolutely no data leakage occurs if your VPN connection drops.

## 📖 What is a Kill Switch and Why Do You Need It?

A **Kill Switch** is a vital security feature in any VPN infrastructure. It acts as an indispensable safety net. Its primary function is to **immediately block your internet access** if the VPN disconnects unexpectedly. 

This proactively prevents your real IP address, DNS queries, and data traffic from being exposed to your Internet Service Provider (ISP) or hostile observers on the same network.

### How does it work exactly?
1. **Constant Monitoring:** The service permanently watches your network interfaces and the active connection to your remote VPN server.
2. **Millisecond Failure Detection:** If the connection drops due to Wi-Fi loss, tunnel instability, or server crashes, GhostTunnel detects it in real-time.
3. **Atomic Traffic Blocking:** The system cuts and blocks ALL device communication with the internet at the Kernel level (`nftables`) **before** any unencrypted packets can leave your machine.
4. **Automatic Restoration:** Internet access remains in a "Panic" (blocked) state until you manually reconnect or the service successfully re-establishes the secure connection.

### Why is it necessary if the VPN is already secure?
Even the most premium VPN clients can experience brief **micro-drops**. Without a robust Kill Switch, your operating system will immediately attempt to route traffic through your local Wi-Fi or Ethernet network, temporarily exposing your identity. GhostTunnel ensures the leak window during these events is exactly **0 milliseconds**.

### 🌟 Why GhostTunnel is Superior (The GhostTunnel Difference)

Most commercial VPNs and open-source scripts rely on **"App-Level"** or **"Reactive"** kill switches. They wait for a ping to fail, and *then* they try to modify your routing table or stop an application. This creates a window of vulnerability (usually 1-3 seconds) where your real IP is exposed. 

**GhostTunnel is fundamentally different:**
- **Proactive & Atomic (Kernel-Level):** GhostTunnel uses `nftables` in atomic transactions. It doesn't modify routes one by one; it completely replaces the kernel's firewall rules in a single millisecond.
- **Strict "FAIL-CLOSED" Design:** If *anything* goes wrong—if the daemon crashes, if there's a bug, or if your VPN provider behaves unexpectedly—GhostTunnel's default reaction is to **lock down the entire network**. Your privacy is always prioritized over your connectivity.
- **Zero-Millisecond Boot Leaks:** Unlike other tools that start *after* the network is up, GhostTunnel injects a strict lockdown policy at `network-pre.target` (before the OS even knows what the internet is). You are protected from the very first millisecond you power on your PC.
- **Cryptographic IPC Authentication:** Inter-Process Communication is protected by `SO_PEERCRED` validation. No unprivileged application or malware on your system can trick the kill switch into dropping its shields.

---

## ⚡ Key Features

* **Zero-Millisecond Boot Leaks:** Total lockdown integrated into the earliest system boot stage (`network-pre.target`), preventing startup leaks.
* **Injectable Atomic Firewall:** Replaces network rules in a single kernel transaction.
* **High-Security IPC Control:** Command-line interface connected directly to the daemon via an ultra-secure UNIX domain socket.
* **Universal Support:** Out-of-the-box compatibility with WireGuard, OpenVPN, and ProtonVPN.
* **Layer 2 & DNS Defense:** Prevention against ARP Spoofing and malicious DHCP DNS injections (C2 DNS Injection).

---

## 🛠️ Professional Installation

Requires superuser (Root) permissions and a modern `systemd`-based Linux distribution.

```bash
# 1. Clone the repository
git clone https://github.com/ikerchborn/ghosttunnel.git
cd ghosttunnel

# 2. Make the installer executable
chmod +x install.sh

# 3. Run the installer (installs dependencies, sets up virtualenv, configures systemd)
sudo ./install.sh
```

---

## 💻 CLI Usage

GhostTunnel runs silently in the background. However, it provides the `ghostctl` utility for immediate real-time interaction via the secure IPC socket:

### 1. Check VPN Shield Status
View which VPN is active, what rules are applied, and real-time leak status:
```bash
sudo ghostctl status
```

### 2. Trigger Manual Panic (Physical Switch)
Instantly cut off the entire network, blocking all incoming and outgoing traffic regardless of your VPN state. Useful if you suspect an imminent local intrusion:
```bash
sudo ghostctl panic
```

### 3. Disable Panic
Revert the manual lockdown and ask the daemon to re-evaluate the network normally:
```bash
sudo ghostctl panic-disable
```

### 4. Emergency Master Unlock
If for any reason you need to completely remove all GhostTunnel defenses (e.g., to diagnose your network without an active tunnel):
```bash
sudo ghostctl unlock-network
```

*(Alternatively, in the event of a critical Python failure, a standalone bash script is available: `sudo ghost-recover`)*

## 🖥️ Desktop GUI Usage

GhostTunnel includes a fully-featured Qt6 desktop graphical interface for users who prefer visual monitoring and control.

### How to Launch the GUI
You can start the GUI from your desktop environment's application menu (if configured), or by running the following command in your terminal:
```bash
ghosttunnel-gui
```
*(Note: You do not need `sudo` to run the GUI. The GUI securely communicates with the root daemon via the IPC socket. Privileged actions like triggering PANIC will prompt you for your password via `pkexec`).*

### GUI Features & Capabilities
- **Live Status Dashboard:** Real-time visual feedback on your VPN status, current mode (e.g., `VPN ACTIVE`, `PANIC`, `VPN CONFLICT`), active firewall rules, and detected DNS servers.
- **One-Click Controls:** Dedicated buttons to trigger PANIC mode, disable PANIC, or execute an emergency network unlock.
- **Dynamic Configuration:** Easily toggle advanced security settings (like blocking IPv6, enabling Stealth Mode, or allowing LAN traffic) via checkboxes. Configurations are saved directly to `/etc/ghosttunnel/config.json`.
- **Activity Log:** A built-in terminal-like panel showing timestamped events, errors, and daemon responses.

---

## 🌍 Supported VPN Providers & Compatibility

GhostTunnel is built with a highly modular and extensible VPN detection system, making it compatible with almost any VPN provider.

### Built-in Support
Out of the box, GhostTunnel auto-detects and seamlessly integrates with:
1. **WireGuard (`wg0`, `wg1`, etc.):** The recommended protocol for modern, high-speed, secure tunnels.
2. **OpenVPN (`tun0`, `tun1`, etc.):** The industry standard protocol.
3. **ProtonVPN (`pvpn-kill`, `pvpn-ipv6rot`, etc.):** Full compatibility with ProtonVPN's official Linux CLI and GUI apps.

### Integrating Custom or Third-Party VPNs

GhostTunnel's agnostic network detection engine is designed to adapt to practically any VPN provider or custom tunneling solution (e.g., Mullvad, IVPN, Tailscale, custom IPSec setups, or proprietary corporate endpoints). Instead of hardcoding support for specific commercial clients, GhostTunnel intelligently monitors system network interfaces matching specific string prefixes.

To secure a custom VPN, follow this comprehensive professional integration procedure:

#### Phase 1: Identify Your VPN Interface Prefix
Before configuring GhostTunnel, you must determine the exact virtual network interface name your VPN client generates when an active encrypted connection is established.

1. Connect to your custom VPN normally.
2. Open your terminal and list all active network interfaces using the standard `ip` command:
   ```bash
   ip link show
   ```
3. Identify the interface corresponding to your VPN tunnel. Common proprietary naming conventions include:
   - `mullvadX` (Mullvad VPN)
   - `tailscaleX` (Tailscale)
   - `ipsecX` (IPSec tunnels)
   - `cscotunX` (Cisco AnyConnect)
4. Note the **prefix** of the interface. For instance, if the interface is named `mullvad0`, the prefix to whitelist is `"mullvad"`. If the interface is `tailscale0`, the prefix is `"tailscale"`.

#### Phase 2: Configure GhostTunnel Core Engine
Once the prefix is identified, you must instruct the GhostTunnel daemon to recognize and protect it. This can be done via the GUI settings or directly through the central JSON configuration file.

**Method A: Via Command Line (Standard for Servers/Headless environments)**
1. Open the primary configuration file using a root-privileged text editor:
   ```bash
   sudo nano /etc/ghosttunnel/config.json
   ```
2. Locate the `"vpn_hints"` array. This array dictates the exact interface prefixes the daemon strictly categorizes as secure tunnels:
   ```json
   "vpn_hints": [
       "wg",
       "tun",
       "pvpn"
   ]
   ```
3. Append your newly identified prefix to this array. Using the Mullvad example:
   ```json
   "vpn_hints": [
       "wg",
       "tun",
       "pvpn",
       "mullvad"
   ]
   ```
4. Save the configuration file and trigger a state reload by restarting the GhostTunnel daemon:
   ```bash
   sudo systemctl restart ghosttunnel
   ```

**Method B: Via Desktop GUI**
1. Launch the GhostTunnel Desktop Application (`ghosttunnel-gui`).
2. Navigate to the **Advanced Configuration** panel.
3. Locate the input field managing **"VPN Hints"** or **"Custom VPN Interfaces"**.
4. Append your prefix (e.g., `mullvad`) to the list.
5. Click **Apply Changes**. The GUI will securely commit the new state to `/etc/ghosttunnel/config.json` and signal the background root daemon via the IPC socket to reload the firewall matrix dynamically.

#### Phase 3: Architectural Verification & Leak Testing
After applying the configuration, it is critical to verify that the fail-closed architecture has successfully enveloped your custom VPN.

1. Ensure your custom VPN is actively connected.
2. Query the GhostTunnel core engine status:
   ```bash
   sudo ghostctl status
   ```
3. Verify the telemetry output. The daemon should explicitly list your custom interface (e.g., `mullvad0`) under the active interfaces section and confirm that the global state is `[VPN ACTIVE]`.
4. **Conduct a Live Leak Test:** Forcefully terminate your VPN client abruptly (e.g., via `killall` or simulating a crash). Immediately attempt to ping an external IP (e.g., `ping 1.1.1.1`).
5. **Expected Result:** The ICMP requests **must fail instantly** (e.g., `Network is unreachable`). This proves the atomic `nftables` have successfully locked down the network routing and prevented any unencrypted data leakage.

---

## 🎯 Common Use Cases & Scenarios

GhostTunnel is designed for individuals who require absolute assurance of their network privacy.

### 1. The Coffee Shop Worker (Public Wi-Fi Protection)
**Scenario:** You connect to an untrusted public Wi-Fi network and launch your VPN. Suddenly, the Wi-Fi router reboots or drops your connection for 3 seconds.
**GhostTunnel Action:** Normally, your laptop would try to reconnect and immediately leak your background apps' data (emails, chat clients) in plain text over the public network. GhostTunnel's `network-pre.target` rules ensure that without the VPN tunnel active, **0 bytes** of data leave your machine. Your traffic remains securely blocked until the VPN reconnects.

### 2. The Privacy Researcher (Anti-DNS Leak & Anti-Tracking)
**Scenario:** Your OS silently accepts malicious DNS servers pushed by a compromised local router (DHCP Injection) to track your web history.
**GhostTunnel Action:** GhostTunnel forces all DNS queries to be resolved exclusively through your VPN tunnel. Local DNS overrides are explicitly ignored unless you manually opt-in via the `trust_local_dns` setting.

### 3. The Torrent / P2P User (ISP Monitoring Prevention)
**Scenario:** You are downloading large files. Your OpenVPN daemon crashes unexpectedly due to a memory error.
**GhostTunnel Action:** As soon as the `tun0` interface vanishes, GhostTunnel's atomic `nftables` immediately drop all P2P traffic. Your real ISP never sees a single packet belonging to the P2P swarm.

### 4. The OPSEC Professional (Physical Security / Panic)
**Scenario:** You detect physical tampering, a malicious actor on the network, or you need to instantly sever all digital ties to your device.
**GhostTunnel Action:** By clicking "TRIGGER PANIC" in the GUI or running `sudo ghostctl panic`, the kernel firewall is instantly replaced with a "Drop All" policy. Even if the VPN is perfectly healthy, your machine goes completely dark and offline.

---

## 🔒 "Fail-Closed" Architecture

The core philosophy of GhostTunnel is that in the event of any logical error, code bug, service crash, VPN provider failure, or environment manipulation, the default system response is to **block everything**. Your identity is more valuable than your connectivity.


<div align="center">
  <p><i>Developed under strict Offensive Security and OPSEC principles.</i></p>
</div>
