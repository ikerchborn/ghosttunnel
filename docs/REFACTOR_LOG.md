# Refactor Log

| File | Lines | Change | Reason |
|------|-------|--------|--------|
| `core/ipc.py` | All | Rewrote `IpcServer` to host two sockets (`ctrl.sock`, `status.sock`). Added GID checking for authorization instead of strict UID=0. Added `broadcast()` method for pub/sub. | Implement Phase 2 Auth Model and Phase 3 Event-driven architecture. |
| `gui/main.py` | 487-566 | Replaced `_run_privileged` with direct `send_command` IPC call. Removed all `pkexec` execution logic. | Eliminate privilege escalation via `pkexec` in GUI. |
| `gui/main.py` | 191-223 | Replaced `time.sleep` polling in `IpcWorker` with blocking `recv` loop connected to `status.sock`. | Implement Phase 3 Event-driven status updates. |
| `daemon.py` | 150-165 | Added `_ipc_unlock_network` handler to process emergency unlocks directly from daemon. Integrated `broadcast` calls when state signatures change. | Support Phase 2 IPC actions and Phase 3 broadcasts. |
| `core/firewall.py` | 44-53 | Added external killswitch detection logic in `__init__` that probes for `PVPN` chains. | Implement Phase 4 non-destructive killswitch. |
| `core/firewall.py` | 380-410 | Overhauled `activate`, `deactivate`, and `_render_rules` to hook into standard `inet filter` using `GHOSTTUNNEL_KS` chains if `EXTERNAL_KS_ACTIVE=True`. | Ensure GhostTunnel never flushes ProtonVPN's killswitch tables. |
| `install.sh` | 38 | Added `groupadd ghosttunnel` and user assignment during installation. | Configure system for Phase 2 GID socket permissions. |
| `gui/main.py` | Comments | Sanitized all lingering `pkexec` comment strings to ensure zero static analysis false positives. | Verification requirement. |
| `gui/main.py` | 191-230 | Implemented EOF handling and exponential backoff retry logic (`1s, 2s, 4s, 8s, 16s`) in `IpcWorker`. | Edge Case 1 & 3: Race condition and daemon reconnect handling. |
| `install.sh` | 39 | Appended explicit stdout warning to user regarding required session restart for group ID. | Edge Case 2: Group ID activation visibility. |
| `core/firewall.py` | 380-410 | Standardized non-destructive chains into `_IN`, `_OUT`, and `_FWD` and updated `deactivate()` to flush all three individually. | Edge Case 4: Idempotence and strict hook separation. |
| `ghost-recover.sh` | 45-50 | Updated recovery script to delete `GHOSTTUNNEL_KS` chains from `inet filter` directly to prevent flushing external VPNs on recovery. | Edge Case 5: Safe recovery without full table deletion. |
