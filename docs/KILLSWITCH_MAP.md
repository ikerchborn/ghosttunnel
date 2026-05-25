# Killswitch Map

## Detected Mechanisms
- **GhostTunnel:** Uses `nftables` (via `nft` command) to create dynamic rules. Panic rules are pre-loaded via `panic.rules`.
- **ProtonVPN:** Typically uses `PVPN_KILLSWITCH` / `PVPN_IPv6_KILLSWITCH` chains or dummy routing tables to sink traffic.

## GhostTunnel Killswitch Behavior
- Blocks all outbound traffic except over the active `vpn_iface`.
- Flushes the table entirely on emergency unlock.
- Automatically applies `panic` rules if VPN disconnects or a leak is detected.

## Conflict Risk Matrix
- **Flush Conflict:** If GhostTunnel runs `nft flush ruleset` or flushes tables that ProtonVPN uses, it breaks ProtonVPN's native killswitch.
- **Chain Overlap:** If both GhostTunnel and ProtonVPN try to drop traffic in the generic `FORWARD` or `OUTPUT` chains without specific jumps, rule order dictates the outcome, causing conflicts.

## Safe Coexistence Rules
1. GhostTunnel MUST use a dedicated custom chain (e.g., `GHOSTTUNNEL_KS`).
2. GhostTunnel MUST append/insert rules into its own chain and only add a `jump` rule from the main `OUTPUT`/`FORWARD` chains.
3. GhostTunnel MUST NOT `flush table inet` completely if external killswitches are detected. It should only flush its own chains.
