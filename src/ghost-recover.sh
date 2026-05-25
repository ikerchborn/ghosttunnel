#!/usr/bin/env bash
# GhostTunnel - Emergency Offline Recovery Script
# Use this script if the daemon crashes or you are completely locked out of the network.
# This script does NOT depend on python or the daemon.
#
# Fixes applied:
#   MED-06      — Replaced 'killall' with PID-based kill via systemctl only
#   SEC-REC-01  — Absolute paths for all system binaries (prevents PATH hijacking)
#   COMPAT-2026 — Handles ProtonVPN NM-based KS (pvpnksintrf0/pvpn-killswitch)
#                 and Mullvad nftables table cleanup

set -eo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ghost-recover)"
  exit 1
fi

echo "[+] ========================================================="
echo "[+] GhostTunnel Emergency Recovery Initiated"
echo "[+] ========================================================="

echo "[*] Stopping GhostTunnel daemon via systemctl..."
/usr/bin/systemctl stop ghosttunnel.service 2>/dev/null || true

# (MED-06) Do NOT use killall — it can kill unrelated processes.
# systemctl stop is authoritative. If it hangs, user can 'kill -9 <PID>' manually.

echo "[*] Removing panic lock file (if any)..."
rm -f /run/ghosttunnel/PANIC.lock 2>/dev/null || true

# ─── nftables cleanup ───────────────────────────────────────────────────────
echo "[*] Flushing GhostTunnel nftables rules..."
# We only remove GhostTunnel-owned tables/chains to avoid breaking other firewalls.
# SEC-REC-01: Use absolute path for nft, detect location first.
NFT_BIN=""
for candidate in /usr/sbin/nft /sbin/nft /usr/bin/nft; do
    if [ -x "$candidate" ]; then
        NFT_BIN="$candidate"
        break
    fi
done

if [ -n "$NFT_BIN" ]; then
    # 1. Remove GhostTunnel's own table (standalone mode)
    "$NFT_BIN" delete table inet ghosttunnel 2>/dev/null || true

    # 2. Remove injected chains when coexisting with Mullvad (into inet filter)
    "$NFT_BIN" delete chain inet filter GHOSTTUNNEL_KS_IN 2>/dev/null || true
    "$NFT_BIN" delete chain inet filter GHOSTTUNNEL_KS_OUT 2>/dev/null || true
    "$NFT_BIN" delete chain inet filter GHOSTTUNNEL_KS_FWD 2>/dev/null || true

    # 3. Remove injected named sets (may be in inet filter when coexisting)
    for s in lan_ipv4 bootstrap_dns_v4 lan_ipv6 bootstrap_dns_v6 vpn_endpoints_v4 vpn_endpoints_v6; do
        "$NFT_BIN" delete set inet filter "$s" 2>/dev/null || true
    done
else
    echo "[!] nft binary not found — manual flush required:"
    echo "    nft delete table inet ghosttunnel"
    echo "    nft delete chain inet filter GHOSTTUNNEL_KS_IN"
    echo "    nft delete chain inet filter GHOSTTUNNEL_KS_OUT"
    echo "    nft delete chain inet filter GHOSTTUNNEL_KS_FWD"
fi

# ─── ProtonVPN NetworkManager kill switch cleanup ─────────────────────────
# Source: ProtonVPN uses NM dummy interfaces, NOT nftables (verified 2026).
# If ProtonVPN KS is stuck, remove these NM connections to restore routing.
# Interfaces: pvpnksintrf0 (killswitch), ipv6leakintrf0 (IPv6 leak protection)
# NM connection names: pvpn-killswitch, pvpn-ipv6leak-protection
NMCLI_BIN=""
for candidate in /usr/bin/nmcli /bin/nmcli; do
    if [ -x "$candidate" ]; then
        NMCLI_BIN="$candidate"
        break
    fi
done

if [ -n "$NMCLI_BIN" ]; then
    echo "[*] Checking for stuck ProtonVPN kill switch NM connections..."
    for conn in pvpn-killswitch pvpn-ipv6leak-protection; do
        if "$NMCLI_BIN" connection show "$conn" &>/dev/null 2>&1; then
            echo "    [!] Found stuck ProtonVPN NM connection: $conn — removing..."
            "$NMCLI_BIN" connection delete "$conn" 2>/dev/null || true
        fi
    done
else
    echo "[*] nmcli not found — skipping ProtonVPN NM connection check."
    echo "    If ProtonVPN KS is stuck, run manually:"
    echo "    nmcli connection delete pvpn-killswitch"
    echo "    nmcli connection delete pvpn-ipv6leak-protection"
fi

# ─── DNS restoration ─────────────────────────────────────────────────────────
echo "[*] Restoring DNS if necessary..."
# systemd-resolved handles DNS on modern distros
/usr/bin/systemctl restart systemd-resolved 2>/dev/null || true

# ─── Routing check ───────────────────────────────────────────────────────────
echo "[*] Checking default gateway..."
# SEC-REC-01: Try known absolute paths for ip binary
if [ -x /sbin/ip ]; then
    /sbin/ip route show default
elif [ -x /usr/sbin/ip ]; then
    /usr/sbin/ip route show default
else
    echo "[!] ip binary not found. Check routing manually."
fi

echo "[+] ========================================================="
echo "[+] Network Unlocked. You should have regular internet access now."
echo "[+] ========================================================="
