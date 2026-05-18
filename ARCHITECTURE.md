# GhostTunnel Architecture & Technical Design

GhostTunnel is a professional, advanced VPN kill switch and OPSEC tool for Linux. It is designed around a strict "FAIL CLOSED" philosophy, ensuring that no traffic leaks outside the authorized VPN tunnel under any circumstances.

This document serves as the canonical technical guide and audit checklist for the repository, matching industry-standard OPSEC models.

---

## 1. Core Architecture and Philosophy

- **Definition**: GhostTunnel acts as a stateful firewall that blocks all outgoing traffic not transiting the active VPN interface (`tunX` / `wgX`). If the VPN drops, there is *no fallback* to the physical interface.
- **Golden Rule (FAIL CLOSED)**: *Deny all, allow by exception.* The default policy for `OUTPUT` and `FORWARD` chains is always `DROP` (silent drop, not reject, to avoid signaling firewall presence).
- **Scope**: Controls IPv4/IPv6 traffic of the host. `INPUT` is restricted to strictly necessary traffic (loopback, established connections).
- **System Service Hook**: The kill switch daemon hooks into systemd via `Before=network-pre.target` to apply the lock *before* any physical network is brought up, eliminating boot-time race conditions.

---

## 2. System Requirements

- **Backend**: `nftables` (replaces legacy iptables). Handles IPv4 and IPv6 uniformly.
- **Capabilities**: The GhostTunnel daemon runs with `CAP_NET_ADMIN` and `CAP_NET_RAW` to manage routing and firewall rules.
- **Persistence**: A custom systemd service (`ghosttunnel.service`) ensures the daemon survives restarts. 
- **IPv6 Security**: GhostTunnel blocks all outgoing IPv6 traffic completely to prevent dual-stack routing leaks, unless explicitly allowed by user configuration (`ipv6_block = false`).

---

## 3. Dynamic VPN Interface Discovery

GhostTunnel does not rely on hardcoded names like `tun0`. It dynamically discovers valid VPN interfaces using the following methodology:

1. **Kernel Routing Validations**: Reads the active default route to identify the egress interface. If the default route points to a `tun`/`wg` interface, it is recognized as active.
2. **Interface Type Detection**: Validates that the interface type is a tunnel (OpenVPN `tun`/`tap`, or WireGuard `wg`).
3. **Assigned Subnets**: Verifies that the VPN interface holds an active private IP address.
4. **Leak Detection**: Validates that the `default route` matches the active VPN interface. If the physical interface hijacks the route, GhostTunnel enters `PANIC` mode.

---

## 4. State Machine Logic

GhostTunnel uses an internal polling state machine that maps to the physical firewall ruleset.

| State / Mode | OUTPUT Policy | Traffic Permitted |
|--------------|---------------|-------------------|
| `BOOT` | **DROP** | Loopback only (eliminates boot race conditions). |
| `VPN-DOWN` | **DROP** | Loopback, DNS bootstrap (to resolve VPN IPs), and UDP/TCP handshakes to configured VPN servers. |
| `VPN-UP` | **DROP** | Loopback, `tunX`/`wgX` traffic, and `ESTABLISHED/RELATED` stateful traffic. |
| `PANIC` | **DROP** | Loopback only. Engaged on routing conflict, explicit user request, or daemon error. |

### Diagram

```text
Boot / User activates killswitch
        │
        ▼
   ┌─────────┐
   │  BOOT   │◄────────────────────────┐
   └────┬────┘                         │
        │                               │
        ▼                               │
   ┌─────────┐    VPN is disconnected  │
   │VPN-DOWN │────────────────────►┌─────────┐
   └─────────┘                     │ VPN-UP  │◄────────┐
        │                          └────┬────┘         │
        │                               │              │
        │         ┌─────────────────────┘              │
        │         │                                    │
        │    VPN drops / default route stolen          │
        │         │                                    │
        │         ▼                                    │
        │    ┌─────────┐                               │
        └───►│  PANIC  │───────────────────────────────┘
             └─────────┘  (User must disable panic via GUI/CLI)
```

---

## 5. Server Switching & Bridge Mode

A common flaw in rudimentary kill switches is blocking the internet so hard that the VPN client cannot resolve or connect to a new server or bridge. GhostTunnel solves this via the `VPN-DOWN` mode:

1. The user requests a server switch or the tunnel drops.
2. GhostTunnel detects the interface drop and shifts to `VPN-DOWN`.
3. The firewall rules are dynamically updated to allow:
   - Queries to specific Bootstrap DNS servers.
   - Handshake packets (UDP 1194, 51820, TCP 443) destined for the new VPN endpoint.
4. Once the new tunnel (`tun1` or `wg0`) is up and verified, GhostTunnel shifts back to `VPN-UP`.

**ProtonVPN Bridges**: If bridge mode is required, the bridge IPs must be resolvable via the Bootstrap DNS, and their ports whitelisted in the `config.json` handshake port list.

---

## 6. Implementation Security Checklist

GhostTunnel natively mitigates common security vectors through its architecture:

- [x] **Race Conditions**: `Before=network-pre.target` in systemd.
- [x] **Stateful Connection Tracking**: `ct state established,related accept` ensures active tunnels don't drop during rotation.
- [x] **DNS Leaks**: `OUTPUT` DNS is locked to specific IP lists; if no list exists, a hard fallback prevents `nftables` syntax errors.
- [x] **IPv6 Leaks**: `ip6tables` / `inet` rules drop `::/0` unless explicitly allowed.
- [x] **Process Tracking**: A strict PID file and IPC socket (`/run/ghosttunnel/ctrl.sock`) separate the GUI/CLI from the daemon context.
- [x] **Emergency Cutoff (Panic)**: If *any* internal daemon process fails, GhostTunnel enters PANIC mode, failing closed automatically.
