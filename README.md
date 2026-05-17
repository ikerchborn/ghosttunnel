<div align="center">
  <h1>🛡️ GhostTunnel</h1>
  <p><strong>Military-Grade VPN Kill Switch & OPSEC Infrastructure for Linux</strong></p>

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
git clone https://github.com/your-username/ghosttunnel.git
cd ghosttunnel

# 2. Run the installer (installs dependencies, sets up virtualenv, configures systemd)
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

---

## 🔒 "Fail-Closed" Architecture

The core philosophy of GhostTunnel is that in the event of any logical error, code bug, service crash, VPN provider failure, or environment manipulation, the default system response is to **block everything**. Your identity is more valuable than your connectivity.


<div align="center">
  <p><i>Developed under strict Offensive Security and OPSEC principles.</i></p>
</div>
