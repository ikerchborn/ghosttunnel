# Security Policy — GhostTunnel

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | ✅ Current         |

## Reporting a Vulnerability

If you discover a security vulnerability in GhostTunnel, **do not open a public GitHub Issue**.

Please report it responsibly by opening a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) via the **Security** tab of this repository.

Include the following in your report:
- A clear description of the vulnerability and its impact
- Steps to reproduce the issue
- Affected version(s)
- Any potential mitigations you have identified

We will respond within **72 hours** and work with you to address the issue before any public disclosure.

## Security Architecture Overview

GhostTunnel is designed around a **FAIL CLOSED** principle. The following security properties are enforced by design:

| Property | Implementation |
|---|---|
| Zero boot-time leak window | `nft -f panic.rules` runs in `ExecStartPre=` before the Python daemon |
| IPC authentication | `SO_PEERCRED` check ensures only UID 0 can send commands |
| Config integrity | File is rejected if not owned by root or world-writable |
| Injection prevention | All IPs, ports, iface names, and table names are validated before use in nftables |
| PATH hijacking prevention | All system binaries resolved via hardcoded path candidates |
| Slow-loris mitigation | IPC recv loop is bounded by both byte limit and chunk count |
| Panic state persistence | `PANIC.lock` file survives daemon restarts |
| Atomic writes | Config and status files written via `tempfile + os.replace()` |

## Known Limitations

- The recovery script (`ghost-recover`) is a last resort and must be run as root manually.
- GUI privilege escalation relies on `pkexec` being correctly configured with a polkit policy on the host system.
- `auto_rotate` is disabled by default because triggering VPN reconnections automatically may itself be a source of brief leak windows in some configurations.
