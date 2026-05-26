"""
GhostTunnel CLI
=================
Fixes applied:
  CRIT-04  — All commands now use real IPC via Unix Domain Socket
  BUG-CLI-01 — PermissionError caught cleanly (no stack traces)
  BUG-CLI-02 — 'status' shows helpful message and daemon state even without IPC
  BUG-CLI-03 — Added 'start' and 'restart' subcommands for convenience
  BUG-CLI-04 — Added 'logs' shortcut subcommand
"""
import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

from ghosttunnel.core.config import Settings
from ghosttunnel.core.system import CommandError, find_binary, require_root, run
from ghosttunnel.core.ipc import send_command

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GhostTunnel — Advanced VPN Kill Switch & OPSEC CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo ghostctl status          # Show current protection status
  sudo ghostctl panic           # Trigger FAIL CLOSED immediately
  sudo ghostctl panic-disable   # Restore normal operation
  sudo ghostctl unlock-network  # Emergency: stop daemon + flush all rules
  sudo ghostctl start           # Start the GhostTunnel daemon
  sudo ghostctl restart         # Restart the daemon
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show the current protection status.")
    sub.add_parser("panic", help="Trigger FAIL CLOSED mode immediately.")
    sub.add_parser("panic-disable", help="Disable panic mode (requires root).")
    sub.add_parser(
        "unlock-network",
        help="Stop daemon and flush all GhostTunnel rules (requires root).",
    )
    sub.add_parser("start", help="Start the GhostTunnel daemon (requires root).")
    sub.add_parser("restart", help="Restart the GhostTunnel daemon (requires root).")
    sub.add_parser("logs", help="Tail the GhostTunnel journal logs.")
    return parser


def status(settings: Settings) -> None:
    """Try IPC first; fall back to reading the status file."""
    ipc_ok = False
    try:
        resp = send_command("status", timeout=3.0)
        ipc_ok = True
        _print_status(resp, source="daemon-ipc")
        return
    except (ConnectionRefusedError, OSError, TimeoutError):
        pass

    # Fallback: read static file
    path = Path(settings.status_path)
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            _print_status(data, source="status-file")
            return
    except PermissionError:
        print("[!] Cannot read status file — try: sudo ghostctl status")
        return
    except Exception as e:
        print(f"[!] Failed to read status file: {e}")
        return

    print("─" * 50)
    print("  GhostTunnel — Status Unknown")
    print("─" * 50)
    print("  Daemon:      NOT RUNNING")
    print("  IPC:         unreachable")
    print("  Status file: not found")
    print()
    print("  Hint: sudo systemctl start ghosttunnel")
    print("─" * 50)


def _print_status(data: dict, source: str = "unknown") -> None:
    """Pretty-print the status dict."""
    mode = data.get("mode", "unknown").upper()
    panic = data.get("panic_mode", False)
    fw = data.get("firewall_active", False)
    vpn_iface = data.get("vpn_iface") or "none"
    vpn_provider = data.get("vpn_provider", "unknown").upper()
    reason = data.get("reason", "")
    phys = ", ".join(data.get("physical_ifaces", [])) or "none"
    dns = ", ".join(data.get("dns_servers", [])) or "none"
    route_probe = data.get("route_probe_iface") or "none"

    mode_colors = {
        "VPN-UP": "\033[32m",      # green
        "VPN-DOWN": "\033[31m",    # red
        "PANIC": "\033[31;1m",     # bold red
        "DISABLED": "\033[33m",    # yellow
        "BOOT": "\033[33m",        # yellow
        "VPN-CONFLICT": "\033[31m",
        "ERROR": "\033[31m",
    }
    reset = "\033[0m"
    color = mode_colors.get(mode, "")

    print("─" * 55)
    print(f"  GhostTunnel Status  [{source}]")
    print("─" * 55)
    print(f"  Mode:          {color}{mode}{reset}")
    print(f"  Panic Active:  {'🔴 YES' if panic else '🟢 NO'}")
    print(f"  Firewall:      {'🟢 ACTIVE' if fw else '🔴 INACTIVE'}")
    print(f"  VPN Provider:  {vpn_provider}")
    print(f"  VPN Interface: {vpn_iface}")
    print(f"  Physical Ifaces: {phys}")
    print(f"  DNS Servers:   {dns}")
    print(f"  Route Probe:   {route_probe}")
    if reason:
        print(f"  Reason:        {reason}")
    print("─" * 55)


def trigger_panic() -> None:
    """Send a real panic command to the daemon via IPC (CRIT-04)."""
    require_root()
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
    """Stop the daemon and flush all GhostTunnel nftables rules via the recovery script."""
    require_root()

    systemctl = find_binary("systemctl")
    print("[*] Stopping GhostTunnel daemon...")
    run([systemctl, "stop", "ghosttunnel.service"], check=False)

    print("[*] Flushing nftables table...")
    # To prevent raw 'delete table' command injections and comply with GT-002,
    # we invoke the recovery script if present, or delete the table via stdin transaction.
    recover_bin = "/usr/local/bin/ghost-recover"
    if not Path(recover_bin).exists():
        recover_bin = "./src/ghost-recover.sh"

    if Path(recover_bin).exists():
        try:
            run([recover_bin], check=True)
        except (CommandError, subprocess.CalledProcessError) as exc:
            print(f"[!] Error running recovery script: {exc}")
    else:
        settings = Settings.load()
        nft = find_binary("nft")
        teardown = f"table inet {settings.table_name}\ndelete table inet {settings.table_name}"
        run([nft, "-f", "-"], input_text=teardown, check=False)

    # Remove panic lock so the daemon doesn't re-enter panic on next start
    from ghosttunnel.core.emergency import PANIC_LOCK_PATH
    Path(PANIC_LOCK_PATH).unlink(missing_ok=True)

    print("[+] Network unlocked. Normal internet access should be restored.")


def start_daemon() -> None:
    """Start the GhostTunnel daemon via systemctl."""
    require_root()
    systemctl = find_binary("systemctl")
    run([systemctl, "start", "ghosttunnel.service"], check=False)
    print("[+] GhostTunnel daemon started.")


def restart_daemon() -> None:
    """Restart the GhostTunnel daemon via systemctl."""
    require_root()
    systemctl = find_binary("systemctl")
    run([systemctl, "restart", "ghosttunnel.service"], check=False)
    print("[+] GhostTunnel daemon restarted.")


def show_logs() -> None:
    """Tail journalctl logs for GhostTunnel."""
    import subprocess
    try:
        subprocess.run(
            ["/usr/bin/journalctl", "-u", "ghosttunnel", "-f", "--no-pager"],
            check=False,
        )
    except KeyboardInterrupt:
        pass
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"[!] Failed to tail logs: {exc}")



def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.load()

    try:
        if args.command == "status":
            status(settings)
        elif args.command == "panic":
            trigger_panic()
        elif args.command == "panic-disable":
            panic_disable()
        elif args.command == "unlock-network":
            unlock_network()
        elif args.command == "start":
            start_daemon()
        elif args.command == "restart":
            restart_daemon()
        elif args.command == "logs":
            show_logs()
    except PermissionError as e:
        print(f"[!] Permission denied: {e}")
        print("    Try: sudo ghostctl " + args.command)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
