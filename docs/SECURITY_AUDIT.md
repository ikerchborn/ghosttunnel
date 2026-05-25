# Security Pre-Audit

## AUDIT 1 — Subprocess / Shell Injection Surface
Analysis of all execution calls (`subprocess`, `os.system`, `os.popen`, `shell=True`, `sudo`, `pkexec`, `exec`, `eval`):

- **`src/ghosttunnel/cli/main.py:198`**
  - **Command:** `subprocess.run(["/usr/bin/journalctl", "-u", "ghosttunnel", "-f", "--no-pager"])`
  - **User Input:** None. Static arguments only.
- **`src/ghosttunnel/core/system.py:121`**
  - **Command:** `subprocess.run(cmd, ...)`
  - **User Input:** Receives list from `run()` wrapper. No `shell=True`. Arguments are validated by caller.
- **`src/ghosttunnel/gui/main.py:531`**
  - **Command:** `subprocess.run([pkexec, ghostctl, subcommand])`
  - **User Input:** `subcommand` originates from internal UI button press, validated against `ALLOWED_SUBCOMMANDS` (`panic`, `panic-disable`, `unlock-network`).
  - **Note:** `pkexec` is used here for privilege escalation. Will be removed in Phase 2.
- **`shell=True`, `eval`, `exec`, `os.system`, `os.popen`:**
  - **NONE FOUND.** (No CRITICAL shell injection risks).

## AUDIT 2 — nftables Destructive Operations
Analysis of all flush/delete operations (`nft flush`, `nft delete`, `iptables -F`):

- **`src/ghosttunnel/cli/main.py:169`**
  - **Command:** `nft delete table inet <settings.table_name>`
- **`src/ghosttunnel/core/firewall.py:369`**
  - **Command:** `nft delete table inet <settings.table_name>`
- **`src/ghosttunnel/core/firewall.py:381`**
  - **Command:** `nft delete table inet <settings.table_name>`
- **`src/ghost-recover.sh:45`**
  - **Command:** `nft delete table inet ghosttunnel`

**Finding:** The codebase currently manages its own isolated **table** (`inet ghosttunnel`). It never executes a global `nft flush ruleset` or `iptables -F`. Deleting the isolated table does not directly flush external VPN chains, but as per Phase 4, we will transition this to a shared table with an isolated **chain** (`GHOSTTUNNEL_KS`) to integrate flawlessly with external killswitches. No CRITICAL full-table flush risks found.

## AUDIT 3 — sudo Internal Usage
Analysis of runtime `sudo` execution:

- **Finding:** No instances of `subprocess.run(["sudo", ...])` exist in the codebase. All occurrences of `sudo` are in `print()` statements for user CLI hints or comments.
- **Status:** PASS. The daemon correctly relies on systemd for root execution, and the GUI (until Phase 2) relies on `pkexec`.

## POST-REFACTOR VERIFICATION
Static verification was executed across the codebase after Phase 5 to ensure strict compliance with security and operational guidelines:

1. **`pkexec` existence:** PASS (0 execution paths. Removed lingering comment references in GUI).
2. **`time.sleep` usage:** PASS (Only used correctly in daemon watchdog loops and reconnect backoffs; removed from GUI `IpcWorker` polling logic).
3. **`shell=True` usage:** PASS (0 results).
4. **`nft flush` usage:** PASS (0 results. Confirmed completely non-destructive firewall strategy).
5. **`nft delete table inet ghosttunnel`:** PASS (Now only explicitly executed when external killswitches are NOT detected, or explicitly overriden in `ghost-recover.sh`).
6. **`SO_PEERCRED|GID` checks:** PASS (`ipc.py` securely unpacks `SO_PEERCRED` and matches against the `ghosttunnel` group).
7. **Socket paths:** PASS (`ctrl.sock` and `status.sock` exist and route correctly).
8. **`GHOSTTUNNEL_KS` chains:** PASS (`firewall.py` dynamically injects into `GHOSTTUNNEL_KS_IN`, `_OUT`, and `_FWD` chains).

### Edge Case Analysis and Fixes

- **CASE 1 (Daemon Startup Race):** Fixed. Implemented exponential backoff in `IpcWorker` (1s, 2s, 4s, 8s, 16s delays) before failing, ensuring it connects properly if the daemon takes longer to bind sockets.
- **CASE 2 (GID Session Apply):** Fixed. Appended explicit echo warning to `install.sh` advising the user to "log out and log in again for group permissions to take effect."
- **CASE 3 (Socket Disconnect/EOF):** Fixed. The `IpcWorker` now catches EOF (an empty line return from `readline()`), explicitly raises a `ConnectionAbortedError`, and loops back through the backoff logic to reconnect automatically instead of crashing.
- **CASE 4 (nftables Chain Idempotence):** Fixed. GhostTunnel explicitly deletes its injected `GHOSTTUNNEL_KS_IN`, `_OUT`, and `_FWD` chains using `delete chain inet filter ... 2>/dev/null` in `self.deactivate()` *before* applying the new rules via `nft -f -`, no "chain already exists" duplication or collision occurs.
- **CASE 5 (ghost-recover.sh Over-deletion):** Fixed. Re-wrote `ghost-recover.sh` to explicitly attempt deletion of `GHOSTTUNNEL_KS_IN`, `_OUT`, and `_FWD` chains inside `inet filter` first. It leaves external ProtonVPN chains completely unharmed even during a hard panic recovery.
