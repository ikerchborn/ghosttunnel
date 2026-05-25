# Reusable Skills

- **Analyzing IPC architecture:** Locate Unix socket paths (`/run/...`), check `socket.AF_UNIX`, verify permission bits and `SO_PEERCRED` checks.
- **Detecting Killswitch conflicts:** Grep for `nft flush`, `iptables -F`, and ensure the firewall logic creates isolated chains rather than modifying global tables.
- **Event-Driven Socket Behavior:** Replace `time.sleep` polling loops with persistent blocking `recv()` loops on the client side, and broadcast state changes from the daemon to connected socket clients.
- **Privilege Escalation changes:** Replace local `subprocess.run(["pkexec"])` wrappers with structured JSON commands over an authenticated socket, ensuring the daemon authorizes the request securely.

## Newly Acquired Skills (GhostTunnel Refactor)
- **Two-Socket IPC Pattern:** Implementing a dual Unix domain socket architecture where one socket (`ctrl.sock`) handles blocking request/response control commands, while a secondary socket (`status.sock`) handles continuous event-driven pub/sub push broadcasts.
- **Non-Destructive nftables Chain Injection:** Dynamically probing for existing VPN killswitches (like ProtonVPN) and injecting custom high-priority isolated chains (`GHOSTTUNNEL_KS_IN`, etc.) directly into the standard `inet filter` table to avoid destructive full-table flushes that break coexistence.
- **Event-Driven GUI with Watchdog:** Converting a GUI from a polling model to a reactive, event-driven model that blocks on a socket `readline()` stream, combined with an exponential backoff reconnect watchdog to gracefully handle daemon disconnects and race conditions.
