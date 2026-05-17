"""
GhostTunnel — Security Unit Tests
====================================
Tests that can run without root or a real Linux system.
Covers sanitization, config validation, IPC protocol logic, and new hardening.
"""
import json
import pytest
import sys
import os

# Ensure src/ is on the path for editable install compatibility in CI
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ghosttunnel.core.system import (
    sanitize_iface,
    sanitize_ip,
    sanitize_port,
    sanitize_table_name,
)
from ghosttunnel.core.config import Settings, _safe_iface_hint
from ghosttunnel.core.models import InterfaceInfo, NetworkSnapshot, VpnState


# -----------------------------------------------------------------------
# Sanitization — interface names
# -----------------------------------------------------------------------
class TestSanitizeIface:
    def test_valid_names(self):
        for name in ("eth0", "wg0", "tun0", "pvpn-abc", "lo", "wlan0"):
            assert sanitize_iface(name) == name

    def test_rejects_injection(self):
        bad = [
            "eth0; drop table",
            "wg0\nnewline",
            '../etc/passwd',
            "a" * 16,           # too long (IFNAMSIZ = 16, valid up to 15)
            "",
            "iface with space",
        ]
        for name in bad:
            with pytest.raises(ValueError):
                sanitize_iface(name)


# -----------------------------------------------------------------------
# Sanitization — IP addresses
# -----------------------------------------------------------------------
class TestSanitizeIp:
    def test_valid_ipv4(self):
        assert sanitize_ip("1.1.1.1") == "1.1.1.1"

    def test_valid_ipv4_cidr(self):
        assert sanitize_ip("10.0.0.0/8") == "10.0.0.0/8"

    def test_valid_ipv6(self):
        assert sanitize_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"

    def test_rejects_non_ip(self):
        bad = ["not-an-ip", "256.1.1.1", "1.1.1.1; drop", "$(id)", ""]
        for addr in bad:
            with pytest.raises(ValueError):
                sanitize_ip(addr)


# -----------------------------------------------------------------------
# Sanitization — ports
# -----------------------------------------------------------------------
class TestSanitizePort:
    def test_valid_ports(self):
        for p in (1, 53, 443, 1194, 51820, 65535):
            assert sanitize_port(p) == p

    def test_rejects_out_of_range(self):
        for p in (0, -1, 65536, 99999):
            with pytest.raises(ValueError):
                sanitize_port(p)

    def test_rejects_non_int(self):
        with pytest.raises(ValueError):
            sanitize_port("443")  # type: ignore


# -----------------------------------------------------------------------
# Sanitization — table names
# -----------------------------------------------------------------------
class TestSanitizeTableName:
    def test_valid(self):
        assert sanitize_table_name("ghosttunnel") == "ghosttunnel"

    def test_rejects_special_chars(self):
        bad = ["ghost tunnel", "ghost;tunnel", "ghost\ntunnel", "a" * 65]
        for name in bad:
            with pytest.raises(ValueError):
                sanitize_table_name(name)


# -----------------------------------------------------------------------
# Config — defaults are safe
# -----------------------------------------------------------------------
class TestSettingsDefaults:
    def test_ipv6_blocked_by_default(self):
        s = Settings()
        assert s.ipv6_block is True

    def test_auto_rotate_disabled_by_default(self):
        s = Settings()
        assert s.auto_rotate is False

    def test_trust_local_dns_disabled_by_default(self):
        """DHCP-injected DNS must NOT be trusted by default (Red Team fix)."""
        s = Settings()
        assert s.trust_local_dns is False

    def test_kill_switch_enabled_by_default(self):
        s = Settings()
        assert s.kill_switch is True

    def test_allow_lan_disabled_by_default(self):
        """LAN exposure is opt-in, not opt-out."""
        s = Settings()
        assert s.allow_lan is False

    def test_bootstrap_dns_are_hardened(self):
        """Bootstrap DNS must not include local resolvers."""
        s = Settings()
        local = {"127.0.0.1", "127.0.0.53", "::1"}
        for dns in s.bootstrap_dns:
            assert dns not in local, f"Local resolver {dns!r} in bootstrap_dns"

    def test_config_validates_bad_fields(self):
        """Unknown or malformed fields in config dict must be ignored."""
        s = Settings()
        # Type mismatch on bool field — should silently skip
        validated = Settings._validate_field("kill_switch", "yes")
        assert validated is None  # string is not bool → rejected


# -----------------------------------------------------------------------
# Config — SEC-CFG-02: sanitize does not crash on bad values, drops them
# -----------------------------------------------------------------------
class TestSettingsSanitization:
    def test_invalid_ip_in_bootstrap_dns_is_dropped(self):
        """An invalid IP in bootstrap_dns should be silently dropped, not raise."""
        s = Settings()
        s.bootstrap_dns = ["1.1.1.1", "not-an-ip", "9.9.9.9"]
        s._sanitize_network_fields()
        assert "not-an-ip" not in s.bootstrap_dns
        assert "1.1.1.1" in s.bootstrap_dns
        assert "9.9.9.9" in s.bootstrap_dns

    def test_invalid_port_is_dropped(self):
        """An invalid port in udp_handshake_ports should be dropped, not raise."""
        s = Settings()
        s.udp_handshake_ports = [53, 99999, 1194]
        s._sanitize_network_fields()
        assert 99999 not in s.udp_handshake_ports
        assert 53 in s.udp_handshake_ports

    def test_invalid_table_name_resets_to_default(self):
        """An invalid table_name (spaces, special chars) resets to 'ghosttunnel'."""
        s = Settings()
        s.table_name = "bad name; drop"
        s._sanitize_network_fields()
        assert s.table_name == "ghosttunnel"

    def test_invalid_vpn_hint_is_dropped(self):
        """An invalid VPN hint (injection chars) is dropped from the list."""
        s = Settings()
        s.vpn_hints = ["wg", "tun", "evil; cmd"]
        s._sanitize_network_fields()
        assert "evil; cmd" not in s.vpn_hints
        assert "wg" in s.vpn_hints


# -----------------------------------------------------------------------
# Config — _safe_iface_hint helper
# -----------------------------------------------------------------------
class TestSafeIfaceHint:
    def test_valid_hint_returns_true(self):
        assert _safe_iface_hint("wg") is True
        assert _safe_iface_hint("pvpn") is True
        assert _safe_iface_hint("tun") is True

    def test_invalid_hint_returns_false(self):
        assert _safe_iface_hint("evil; cmd") is False
        assert _safe_iface_hint("a" * 20) is False
        assert _safe_iface_hint("") is False


# -----------------------------------------------------------------------
# GUI — subcommand allowlist (SEC-GUI-01)
# -----------------------------------------------------------------------
class TestGuiSubcommandAllowlist:
    def test_allowed_subcommands_are_declared(self):
        """The GUI must have a non-empty allowlist of subcommands."""
        # Import at module level to avoid Qt instantiation
        import importlib
        import unittest.mock as mock

        # Patch PyQt6 imports so we can import the module without a display
        qt_modules = {
            "PyQt6": mock.MagicMock(),
            "PyQt6.QtCore": mock.MagicMock(),
            "PyQt6.QtGui": mock.MagicMock(),
            "PyQt6.QtWidgets": mock.MagicMock(),
        }
        with mock.patch.dict("sys.modules", qt_modules):
            import ghosttunnel.gui.main as gui_mod
            importlib.reload(gui_mod)
            allowed = gui_mod.ALLOWED_SUBCOMMANDS
            assert "panic" in allowed
            assert "panic-disable" in allowed
            assert "unlock-network" in allowed
            # Should NOT allow arbitrary commands
            assert "rm -rf /" not in allowed


# -----------------------------------------------------------------------
# Models — InterfaceInfo
# -----------------------------------------------------------------------
class TestInterfaceInfo:
    def test_unknown_is_not_up(self):
        """UNKNOWN operstate must NOT be treated as UP (MED-05)."""
        iface = InterfaceInfo(name="wg0", state="UNKNOWN")
        assert iface.is_up is False

    def test_up_is_up(self):
        iface = InterfaceInfo(name="eth0", state="UP")
        assert iface.is_up is True

    def test_down_is_not_up(self):
        iface = InterfaceInfo(name="eth0", state="DOWN")
        assert iface.is_up is False

    def test_loopback_is_not_physical(self):
        iface = InterfaceInfo(name="lo", is_loopback=True)
        assert iface.is_physical is False

    def test_virtual_is_not_physical(self):
        iface = InterfaceInfo(name="wg0", is_virtual=True)
        assert iface.is_physical is False


# -----------------------------------------------------------------------
# Models — NetworkSnapshot
# -----------------------------------------------------------------------
class TestNetworkSnapshot:
    def test_physical_ifaces_excludes_loopback(self):
        lo = InterfaceInfo(name="lo", is_loopback=True)
        eth = InterfaceInfo(name="eth0", state="UP")
        snap = NetworkSnapshot(interfaces={"lo": lo, "eth0": eth})
        physical = snap.physical_ifaces
        assert all(i.name != "lo" for i in physical)
        assert any(i.name == "eth0" for i in physical)


# -----------------------------------------------------------------------
# IPC — protocol validation
# -----------------------------------------------------------------------
class TestIpcProtocol:
    def test_send_command_raises_on_malformed_response(self):
        """send_command() must raise ConnectionRefusedError if daemon returns garbage."""
        import socket
        import threading
        import tempfile
        import os
        from ghosttunnel.core.ipc import send_command, _RECV_LIMIT

        # Create a temp socket that returns non-JSON data
        tmp = tempfile.mktemp(suffix=".sock")
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(tmp)
        server_sock.listen(1)

        def _bad_server():
            conn, _ = server_sock.accept()
            conn.recv(1024)
            conn.sendall(b"not json at all\n")
            conn.close()
            server_sock.close()

        t = threading.Thread(target=_bad_server, daemon=True)
        t.start()

        # Patch the SOCKET_PATH to our temp socket
        import ghosttunnel.core.ipc as ipc_mod
        original = ipc_mod.SOCKET_PATH
        ipc_mod.SOCKET_PATH = tmp
        try:
            with pytest.raises(ConnectionRefusedError):
                send_command("status")
        finally:
            ipc_mod.SOCKET_PATH = original
            t.join(timeout=2)
            try:
                os.unlink(tmp)
            except OSError:
                pass
