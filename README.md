<div align="center">
  <h1>🛡️ GhostTunnel</h1>
  <p><strong>VPN Kill Switch & OPSEC Infrastructure for Linux</strong></p>

  [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Security Policy](https://img.shields.io/badge/Security-Policy-red.svg)](./SECURITY.md)
  [![Security: Atomic](https://img.shields.io/badge/Security-Atomic_Nftables-red.svg)](#fail-closed-architecture)
</div>

---

## 📖 Introduction

**GhostTunnel** is an enterprise-grade, daemonized OPSEC (Operations Security) infrastructure specifically engineered for **Debian-based Linux systems** (Debian, Ubuntu, Kali, ParrotOS). It acts as the ultimate fail-safe for your privacy by implementing a strict **FAIL-CLOSED** architecture. 

If your VPN drops for even a millisecond, GhostTunnel guarantees that absolutely zero unencrypted packets will leave your machine. By using atomic `nftables` operations at the kernel level, it secures your network before your operating system even finishes booting.

Designed exclusively for the Debian network stack to guarantee absolute stability and predictable kernel behavior, GhostTunnel provides an impenetrable shield around your internet traffic—whether you are a privacy researcher, an investigative journalist, a security professional, or simply an enterprise user who refuses to compromise on network integrity.

---

## ⚡ The GhostTunnel Difference

Most commercial VPN clients use reactive, application-level kill switches. They monitor a connection, wait for it to fail, and *then* react to block traffic. This creates a critical window of vulnerability (often 1-3 seconds) where your real IP address leaks to your ISP.

**GhostTunnel operates differently:**
- **Proactive Kernel Integration:** Using atomic `nftables` transactions, GhostTunnel replaces the entire system firewall matrix in a fraction of a millisecond.
- **Pre-Boot Lockdown:** Protection starts at `network-pre.target`. Your system is locked down *before* network interfaces are even initialized.
- **Strict "FAIL-CLOSED" Philosophy:** If the daemon crashes, if a bug occurs, or if your VPN provider is experiencing conflicts, the system defaults to blocking all traffic. **Privacy over Connectivity, always.**
- **Secure IPC Socket:** User interaction is handled via a root-authenticated Unix Domain Socket (`SO_PEERCRED`), preventing malicious local processes from tampering with your security state.

---

## 🛠️ Installation & Deployment

GhostTunnel is built exclusively for modern, `systemd`-driven **Debian-based distributions**. It requires root privileges for installation, service deployment, and kernel-level firewall management.

### 1. Compile Native Binaries (Optional but Recommended)
You can compile GhostTunnel into standalone Linux executables (`.exe` equivalents) for maximum performance and professional integration, avoiding reliance on Python virtual environments.

```bash
# Clone the repository
git clone https://github.com/ikerchborn/ghosttunnel.git
cd ghosttunnel

# Make the compiler executable and run it
chmod +x build_binaries.sh
./build_binaries.sh
```
This will create native binaries in the `dist_bin/` folder.

### 2. Automated Installation
We provide a secure installation script that safely manages dependencies and configures the `systemd` daemon. If you ran the compilation step above, it will automatically install the native binaries and the Desktop App shortcut.

```bash
chmod +x install.sh
sudo ./install.sh
```

### 3. First-Time Activation (IMPORTANT)
**GhostTunnel DOES NOT start automatically upon installation.** This ensures that you do not get unexpectedly locked out of your network while configuring your VPN.

To activate the FAIL-CLOSED killswitch and lock down your network for the first time, you must manually start the daemon:
```bash
sudo systemctl start ghosttunnel
```
Once started, `ghostd` will automatically apply the boot-time lockdown rules on every future system reboot.

---

## 💻 CLI Manual (`ghostctl`)

GhostTunnel runs silently via `systemd`. However, the `ghostctl` Command Line Interface provides real-time control over the daemon via the secure IPC socket.

### Real-Time Telemetry
Check the active VPN provider, interface, current firewall mode, and DNS status:
```bash
sudo ghostctl status
```

### Physical Panic Switch
Instantly cut off the entire network, blocking all incoming and outgoing traffic regardless of your VPN state. Crucial if you suspect an imminent local intrusion or physical compromise:
```bash
sudo ghostctl panic
```

### Restore Operations
Disable panic mode and instruct the daemon to safely re-evaluate the network state:
```bash
sudo ghostctl panic-disable
```

### Daemon Management
Restart or start the daemon gracefully:
```bash
sudo ghostctl restart
sudo ghostctl start
```

### Emergency Network Unlock
If you need to completely remove all GhostTunnel defenses (e.g., to diagnose a broken network interface without an active tunnel), this will stop the daemon and flush the `nftables` rules.
> **Warning:** Your real IP will be exposed to your ISP.
```bash
sudo ghostctl unlock-network
```
*(Alternatively, a standalone recovery script `sudo ghost-recover` is provided for emergencies if Python itself fails).*

### Audit Logs
Monitor the real-time background decisions made by the security engine:
```bash
sudo ghostctl logs
```

---

## 🖥️ Graphical User Interface (GUI)

GhostTunnel includes a fully-featured Qt6 desktop application for visual telemetry and control.

### How to Access the GUI
1. **From your Desktop Menu (Recommended):**
   Open your system's application launcher (Activities, Whisker Menu, etc.), search for **"GhostTunnel"**, and click the icon.
2. **From the Terminal:**
   You can also launch it directly by typing:
   ```bash
   ghostgui
   # or
   ghosttunnel-gui
   ```

*Note: You do not need to run the GUI as root initially. If you attempt a privileged action (like saving the config or triggering a panic), the GUI will automatically prompt you for your password via `pkexec`.*

### GUI Capabilities
- **Live Status Dashboard:** Visual feedback on your VPN status, panic state, active firewall rules, and routed physical interfaces.
- **One-Click Controls:** Dedicated buttons to trigger PANIC, Disable PANIC, or Emergency Unlock. (Requires `pkexec` authorization).
- **Activity Log:** Real-time stream of daemon events and status changes.
- **Dynamic Configuration:** Toggle advanced features directly from the UI without touching the configuration files.

---

## ⚙️ Advanced Configuration (`config.json`)

GhostTunnel's behavior can be customized via the GUI or by editing `/etc/ghosttunnel/config.json`. The daemon will read these changes upon restart.

### Core OPSEC Settings
- **`kill_switch`**: (Default: `true`) Master toggle for the fail-closed architecture.
- **`ipv6_block`**: (Default: `true`) Completely drops all IPv6 traffic to prevent IPv6 routing leaks, a common vulnerability in modern OS configurations.
- **`stealth_mode`**: (Default: `false`) Drops ICMP (Ping) packets and randomizes specific network signatures to hide your machine from local network scanning.
- **`trust_local_dns`**: (Default: `false`) **CRITICAL:** If false, GhostTunnel ignores DNS servers provided by your local router (DHCP), preventing C2 DNS Injection and rogue ISP tracking. It will exclusively route DNS through your VPN or secure bootstrap resolvers.

### Advanced Routing
- **`allow_lan`**: (Default: `false`) Permits traffic to local subnets (e.g., `192.168.x.x`). Enable this if you need to access local printers or NAS devices while the VPN is active.
- **`allow_forwarding`**: (Default: `false`) Enables NAT Masquerading and IP Forwarding. Required if you are running Docker containers, VMs (KVM/VirtualBox), or using HackTheBox setups through the VPN tunnel.

### Auto-Rotation & Resilience
- **`auto_rotate`**: (Default: `false`) If the active VPN fails, GhostTunnel will automatically attempt to reconnect or rotate to the next available VPN provider defined in `vpn_priority`.
- **`vpn_priority`**: Order of preference for VPN auto-rotation. (e.g., `["protonvpn", "wireguard", "openvpn"]`).

---

## 🌍 VPN Integration & Compatibility

GhostTunnel features an agnostic network detection engine. It does not rely on fragile application hooks; instead, it monitors the actual routing layer.

### Out-of-the-Box Support
1. **WireGuard (`wg0`, `mullvad0`, `nordlynx`):** Native detection for standard WireGuard implementations.
2. **OpenVPN (`tun0`, `tap0`):** Full compatibility with legacy OpenVPN setups.
3. **ProtonVPN (`pvpn-`, `proton0`):** Deep integration with both the official ProtonVPN CLI and the modern GUI, natively resolving internal kill switch conflicts.

### Integrating Custom VPN Providers

If you use a proprietary or custom VPN (e.g., Tailscale, custom IPSec, corporate VPNs), you can easily map it into GhostTunnel's fail-closed matrix.

1. **Identify the Interface:** Connect to your VPN and run `ip link show`. Identify the prefix of the virtual interface (e.g., if the interface is `tailscale0`, the prefix is `tailscale`).
2. **Add to Configuration:** Open `/etc/ghosttunnel/config.json` (or use the GUI) and add the prefix to the `"vpn_hints"` array:
   ```json
   "vpn_hints": [
       "wg",
       "tun",
       "pvpn",
       "tailscale"
   ]
   ```
3. **Restart Daemon:** `sudo systemctl restart ghosttunnel`.
4. GhostTunnel will now recognize `tailscale` as a secure tunnel and wrap it in the atomic kill switch rules.

---

## 🛡️ Threat Modeling & Mitigations

GhostTunnel is engineered to defend against specific, high-risk OPSEC failures:

| Threat | GhostTunnel Mitigation |
|--------|-----------------------|
| **Boot-time Leaks** | Applies `panic.rules` at `network-pre.target` before OS services can phone home. |
| **Micro-Drops (Wi-Fi flicker)** | Atomic `nftables` replacement ensures the drop policy is enforced in < 1ms. |
| **Rogue DNS (DHCP Spoofing)** | Discards local router DNS; forces all lookups through secure endpoints. |
| **IPv6 Sideloading** | Aggressive, system-wide IPv6 dropping by default. |
| **Malware Disabling Security** | Daemon strictly validates `SO_PEERCRED`. Only `root` can modify the security state. |

---

<div align="center">
  <p><i>Privacy is not a privilege; it's a fundamental right.</i></p>
  <p><i>Developed under strict Offensive Security principles.</i></p>
</div>
