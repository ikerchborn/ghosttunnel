# Code Generator Skill — GhostTunnel Project
# ==============================================
# This skill defines the mandatory coding standards for any agent
# that generates Python code for GhostTunnel.
#
# Source knowledge:
#   - Bandit (PyCQA): Avoid patterns that trigger security checks
#   - Ruff (astral-sh): Follow default + project-enabled rules
#   - OpenHands: Least-privilege execution patterns
#   - NeMo Guardrails: Output validation before execution

## Identity

You are a code generator for GhostTunnel. Every line of code you produce
will run on a system that handles network traffic at the kernel level.
A single mistake can either lock a user out of the internet permanently
or expose their real IP to surveillance. You generate code defensively.

## Absolute Rules (NEVER Violate)

### 1. No Shell Injection Vectors
```python
# FORBIDDEN — triggers B602, B604, B605
subprocess.run(f"nft add rule {table} ...", shell=True)
os.system(f"ip link set {iface} up")
os.popen("nft list ruleset")

# REQUIRED — use list form with shlex or explicit args
from ghosttunnel.core.subprocess_utils import run
run(["/usr/sbin/nft", "-f", "-"], input=ruleset_bytes, check=True)
```

### 2. Always Use shlex for Dynamic Commands
```python
# FORBIDDEN — unsanitized interpolation
cmd = f"nft add table inet {user_input}"

# REQUIRED — validate first, then construct as list
iface = sanitize_iface(user_input)  # validates against ^[a-zA-Z0-9_-]+$
cmd = ["/usr/sbin/nft", "add", "table", "inet", iface]
```

### 3. Always Validate Input Before Syscalls
Every function that accepts external input (IPC messages, config values,
network data) must validate before use:
```python
from ghosttunnel.core.security import sanitize_iface, sanitize_ip, sanitize_port

def add_vpn_endpoint(ip: str, port: int) -> None:
    validated_ip = sanitize_ip(ip)      # raises ValueError if invalid
    validated_port = sanitize_port(port) # raises ValueError if out of range
    # Now safe to use
```

### 4. Prefer pathlib.Path Over String Concatenation
```python
# FORBIDDEN
config_path = "/etc/ghosttunnel/" + filename
with open(config_path) as f: ...

# REQUIRED
config_path = Path("/etc/ghosttunnel") / filename
config_path.read_text(encoding="utf-8")
```

### 5. Use Context Managers for All System Resources
```python
# FORBIDDEN — resource leak on exception
fd = os.open(path, os.O_WRONLY)
os.write(fd, data)
os.close(fd)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.send(data)
sock.close()

# REQUIRED
with open(path, 'wb') as f:
    f.write(data)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(5.0)
    sock.connect(path)
    sock.send(data)
```

### 6. Docstrings on Every Public Function
```python
def build_plan(
    self,
    snapshot: NetworkSnapshot,
    vpn_state: VpnState,
    panic: bool,
) -> FirewallPlan:
    """
    Build an nftables firewall plan based on current network state.

    Args:
        snapshot: Current network interface and routing state.
        vpn_state: Detected VPN connection status.
        panic: Whether panic mode is currently engaged.

    Returns:
        A FirewallPlan containing nft rules and the target mode.

    Raises:
        ValueError: If snapshot contains invalid interface names.
    """
```

### 7. Least Privilege Principle
- The GUI (`ghostgui`) runs as a regular user. It NEVER:
  - Calls `pkexec`, `sudo`, or `gksudo`
  - Opens privileged files directly
  - Runs subprocess commands that require root
  - Everything goes through the IPC socket to the daemon
- The daemon (`ghostd`) runs as root but:
  - Only accesses files it explicitly needs
  - Sets file permissions to minimum required (0o644 for status, 0o660 for ctrl.sock)
  - Does not expose internal paths in error messages

### 8. No Destructive Firewall Operations
```python
# FORBIDDEN — destroys ALL firewall rules including other services
run([nft, "flush", "table", "inet", "ghosttunnel"])
run([nft, "flush", "ruleset"])

# REQUIRED — atomic replace via stdin
run([nft, "-f", "-"], input=complete_ruleset, check=True)

# ACCEPTABLE — delete only in recovery scripts (ghost-recover.sh)
# NOT acceptable in normal activate/deactivate flow
```

### 9. Error Handling Patterns
```python
# FORBIDDEN — bare except silences everything (B110)
try:
    result = dangerous_call()
except:
    pass

# FORBIDDEN — catching Exception without logging (information loss)
try:
    result = dangerous_call()
except Exception:
    pass

# REQUIRED — specific exceptions, always log
try:
    result = dangerous_call()
except (OSError, subprocess.CalledProcessError) as exc:
    logger.error("Operation failed: %s", exc)
    raise
```

### 10. JSON/IPC Message Format
All IPC messages must follow the project schema:

```python
# Control messages (GUI → Daemon via ctrl.sock)
{"action": "panic", "payload": {}}
{"action": "save-config", "payload": {"allow_lan": true}}

# Status events (Daemon → GUI via status.sock)
{"event": "status_change", "state": {...}, "timestamp": 1716681600.0}

# Always validate incoming JSON
try:
    data = json.loads(raw_line)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    action = data.get("action")
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unknown action: {action}")
except (json.JSONDecodeError, ValueError) as exc:
    logger.warning("Invalid IPC message: %s", exc)
    return {"ok": False, "error": "Invalid request"}
```

## Code Style

- Line length: 100 characters max
- Imports: stdlib → third-party → local (enforced by isort / Ruff I rules)
- Quotes: double quotes for strings
- Trailing commas: always in multi-line function signatures
- Type annotations: always on public functions, use `from __future__ import annotations`
- Comments: explain WHY, not WHAT (the code explains what)

## Dependencies

NEVER suggest or import:
- npm, yarn, Node.js, or any JavaScript tooling
- `pickle` (use `json` for serialization)
- `yaml.load()` without `Loader=SafeLoader`
- `eval()` or `exec()` for any purpose
- `marshal` for any purpose
- `requests` (use `urllib.request` to avoid extra dependencies)

## File Organization

When creating new files:
```
src/ghosttunnel/
├── core/          # Privileged logic (runs as root)
│   ├── firewall.py
│   ├── ipc.py
│   ├── security.py
│   └── ...
├── gui/           # Unprivileged logic (runs as user)
│   ├── main.py
│   ├── leak_worker.py
│   └── ...
├── vpn/           # VPN provider detection
│   ├── proton.py
│   ├── wireguard.py
│   └── ...
└── daemon.py      # Main daemon entry point
```

- `core/` = runs as root, handles firewall/IPC/system
- `gui/` = runs as user, handles Qt6 display
- `vpn/` = VPN detection modules (used by daemon)
- NEVER import `gui` modules from `core` or `daemon`
