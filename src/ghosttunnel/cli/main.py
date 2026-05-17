"""
GhostTunnel CLI
=================
Fixes applied:
  CRIT-04 — All commands now use real IPC via Unix Domain Socket
"""
import argparse
import json
import logging
import sys
from pathlib import Path

from ghosttunnel.core.config import Settings
from ghosttunnel.core.system import require_root
from ghosttunnel.core.ipc import send_command

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GhostTunnel — Advanced VPN Kill Switch & OPSEC CLI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show the current protection status.")
    sub.add_parser("panic", help="Trigger FAIL CLOSED mode immediately.")
    sub.add_parser("panic-disable", help="Disable panic mode (requires root).")
    sub.add_parser(
        "unlock-network",
        help="Stop daemon and flush all GhostTunnel rules (requires root).",
    )
    return parser


def status(settings: Settings) -> None:
    """Try IPC first; fall back to reading the status file."""
    try:
        resp = send_command("status")
        print(json.dumps(resp, indent=2))
        return
    except (ConnectionRefusedError, OSError):
        pass

    # Fallback: read static file
    path = Path(settings.status_path)
    if not path.exists():
        print("Status file not found. Is the daemon running?")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"Failed to read status: {e}")


def trigger_panic() -> None:
    """Send a real panic command to the daemon via IPC (CRIT-04)."""
    try:
        resp = send_command("panic")
        if resp.get("ok"):
            print("[!] PANIC MODE ENGAGED — all network traffic is now blocked.")
        else:
            print(f"[!] Daemon returned error: {resp.get('error', 'unknown')}")
    except ConnectionRefusedError as e:
        print(f"[!] Cannot reach daemon: {e}")
        print("    If the daemon is not running, network should already be locked by boot rules.")
        sys.exit(1)


def panic_disable() -> None:
    """Send a panic-disable command to the daemon via IPC (CRIT-04)."""
    require_root()
    try:
        resp = send_command("panic-disable")
        if resp.get("ok"):
            print("[+] Panic mode disabled. The daemon will re-evaluate on the next cycle.")
        else:
            print(f"[!] Daemon returned error: {resp.get('error', 'unknown')}")
    except ConnectionRefusedError as e:
        print(f"[!] Cannot reach daemon: {e}")
        sys.exit(1)


def unlock_network() -> None:
    """Stop the daemon and flush all GhostTunnel nftables rules."""
    require_root()
    from ghosttunnel.core.system import run, find_binary

    systemctl = find_binary("systemctl")
    print("[*] Stopping GhostTunnel daemon...")
    run([systemctl, "stop", "ghosttunnel.service"], check=False)

    print("[*] Flushing nftables table...")
    settings = Settings.load()
    nft = find_binary("nft")
    run([nft, "delete", "table", "inet", settings.table_name], check=False)

    # Remove panic lock so the daemon doesn't re-enter panic on next start
    from ghosttunnel.core.emergency import PANIC_LOCK_PATH
    Path(PANIC_LOCK_PATH).unlink(missing_ok=True)

    print("[+] Network unlocked. Normal internet access should be restored.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.load()

    if args.command == "status":
        status(settings)
    elif args.command == "panic":
        trigger_panic()
    elif args.command == "panic-disable":
        panic_disable()
    elif args.command == "unlock-network":
        unlock_network()


if __name__ == "__main__":
    main()
