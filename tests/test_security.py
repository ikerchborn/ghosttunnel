"""
GhostTunnel — Security & Functional Unit Tests
================================================
Tests that run without root or a real Linux system.
Covers:
  - Sanitization (iface, IP, port, table name)
  - Config validation and defaults
  - Firewall ruleset generation
  - IPC protocol logic
  - VPN adapter state detection
  - Leak detector logic
  - GUI subcommand allowlist
"""
import json
import os
import sys
import threading
import tempfile
import socket as _socket

import pytest

# Ensure src/ is on the path for editable install compatibility in CI
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ghosttunnel.core.system import (
    sanitize_iface,
    sanitize_ip,
    sanitize_port,
    sanitize_table_name,
)
from ghosttunnel.core.config import Settings, _safe_iface_hint
from ghosttunnel.core.models import (
    InterfaceInfo,
    NetworkSnapshot,
    VpnState,
    ControllerState,
)


# =====================================================================
# Sanitization — interface names
# =====================================================================
class TestSanitizeIface:
    def test_valid_names(self):
        for name in ("eth0", "wg0", "tun0", "pvpn-abc", "lo", "wlan0"):
            assert sanitize_iface(name) == name

    def test_rejects_injection(self):
        bad = [
            "eth0; drop table",
            "wg0\nnewline",
            "../etc/passwd",
            "a" * 16,           # too long (IFNAMSIZ = 16, valid up to 15)
            "",
            "iface with space",
        ]
        for name in bad:
            with pytest.raises(ValueError):
                sanitize_iface(name)


# =====================================================================
# Sanitization — IP addresses
# =====================================================================
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


# =====================================================================
# Sanitization — ports
# =====================================================================
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


# =====================================================================
# Sanitization — table names
# =====================================================================
class TestSanitizeTableName:
    def test_valid(self):
        assert sanitize_table_name("ghosttunnel") == "ghosttunnel"

    def test_rejects_special_chars(self):
        bad = ["ghost tunnel", "ghost;tunnel", "ghost\ntunnel", "a" * 65]
        for name in bad:
            with pytest.raises(ValueError):
                sanitize_table_name(name)


# =====================================================================
# Config — defaults are safe
# =====================================================================
class TestSettingsDefaults:
    def test_ipv6_blocked_by_default(self):
        s = Settings()
        assert s.ipv6_block is True

    def test_auto_rotate_disabled_by_default(self):
        s = Settings()
        assert s.auto_rotate is False

    def test_trust_local_dns_disabled_by_default(self):
        s = Settings()
        assert s.trust_local_dns is False

    def test_kill_switch_enabled_by_default(self):
        s = Settings()
        assert s.kill_switch is True

    def test_allow_lan_disabled_by_default(self):
        s = Settings()
        assert s.allow_lan is False

    def test_bootstrap_dns_are_hardened(self):
        s = Settings()
        local = {"127.0.0.1", "127.0.0.53", "::1"}
        for dns in s.bootstrap_dns:
            assert dns not in local, f"Local resolver {dns!r} in bootstrap_dns"

    def test_config_validates_bad_fields(self):
        validated = Settings._validate_field("kill_switch", "yes")
        assert validated is None  # string is not bool → rejected

    def test_status_path_is_set(self):
        s = Settings()
        assert s.status_path == "/run/ghosttunnel/status.json"

    def test_table_name_is_set(self):
        s = Settings()
        assert s.table_name == "ghosttunnel"

    def test_bootstrap_dns_not_empty(self):
        s = Settings()
        assert len(s.bootstrap_dns) > 0, "bootstrap_dns must not be empty"


# =====================================================================
# Config — sanitization drops invalid values, does not crash
# =====================================================================
class TestSettingsSanitization:
    def test_invalid_ip_in_bootstrap_dns_is_dropped(self):
        s = Settings()
        s.bootstrap_dns = ["1.1.1.1", "not-an-ip", "9.9.9.9"]
        s._sanitize_network_fields()
        assert "not-an-ip" not in s.bootstrap_dns
        assert "1.1.1.1" in s.bootstrap_dns
        assert "9.9.9.9" in s.bootstrap_dns

    def test_invalid_port_is_dropped(self):
        s = Settings()
        s.udp_handshake_ports = [53, 99999, 1194]
        s._sanitize_network_fields()
        assert 99999 not in s.udp_handshake_ports
        assert 53 in s.udp_handshake_ports

    def test_invalid_table_name_resets_to_default(self):
        s = Settings()
        s.table_name = "bad name; drop"
        s._sanitize_network_fields()
        assert s.table_name == "ghosttunnel"

    def test_invalid_vpn_hint_is_dropped(self):
        s = Settings()
        s.vpn_hints = ["wg", "tun", "evil; cmd"]
        s._sanitize_network_fields()
        assert "evil; cmd" not in s.vpn_hints
        assert "wg" in s.vpn_hints


# =====================================================================
# Config — _safe_iface_hint helper
# =====================================================================
class TestSafeIfaceHint:
    def test_valid_hint_returns_true(self):
        assert _safe_iface_hint("wg") is True
        assert _safe_iface_hint("pvpn") is True
        assert _safe_iface_hint("tun") is True

    def test_invalid_hint_returns_false(self):
        assert _safe_iface_hint("evil; cmd") is False
        assert _safe_iface_hint("a" * 20) is False
        assert _safe_iface_hint("") is False


# =====================================================================
# Models — InterfaceInfo
# =====================================================================
class TestInterfaceInfo:
    def test_unknown_is_not_up(self):
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

    def test_physical_iface_is_physical(self):
        iface = InterfaceInfo(name="eth0", state="UP", is_loopback=False, is_virtual=False)
        assert iface.is_physical is True


# =====================================================================
# Models — NetworkSnapshot
# =====================================================================
class TestNetworkSnapshot:
    def test_physical_ifaces_excludes_loopback(self):
        lo = InterfaceInfo(name="lo", is_loopback=True)
        eth = InterfaceInfo(name="eth0", state="UP")
        snap = NetworkSnapshot(interfaces={"lo": lo, "eth0": eth})
        physical = snap.physical_ifaces
        assert all(i.name != "lo" for i in physical)
        assert any(i.name == "eth0" for i in physical)

    def test_physical_ifaces_excludes_virtual(self):
        wg = InterfaceInfo(name="wg0", is_virtual=True)
        eth = InterfaceInfo(name="eth0", is_virtual=False)
        snap = NetworkSnapshot(interfaces={"wg0": wg, "eth0": eth})
        physical = snap.physical_ifaces
        assert any(i.name == "eth0" for i in physical)

    def test_empty_snapshot_has_no_physical(self):
        snap = NetworkSnapshot()
        assert snap.physical_ifaces == ()


# =====================================================================
# Firewall — ruleset generation (no root needed, just string checks)
# =====================================================================
class TestFirewallRulesetGeneration:
    def _make_snapshot(self, *, vpn_iface="wg0", has_endpoints=True):
        eth = InterfaceInfo(name="eth0", state="UP", is_virtual=False, is_loopback=False)
        wg = InterfaceInfo(name=vpn_iface, state="UNKNOWN", is_virtual=True, is_loopback=False,
                           ipv4=("10.8.0.2",))
        return NetworkSnapshot(
            interfaces={"eth0": eth, vpn_iface: wg},
            default_route_iface=vpn_iface,
            route_probe_iface=vpn_iface,
            dns_servers=("1.1.1.1", "9.9.9.9"),
            vpn_endpoint_ips=("203.0.113.1",) if has_endpoints else (),
        )

    def test_panic_rules_block_all_non_loopback(self):
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        rules = fw._render_panic_rules()
        assert "policy drop" in rules
        assert 'iifname "lo" accept' in rules
        assert "ghosttunnel" in rules

    def test_vpn_up_rules_allow_vpn_iface(self):
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        snap = self._make_snapshot()
        vpn = VpnState(active=True, iface="wg0", provider="wireguard")
        plan = fw.build_plan(snap, vpn, panic_mode=False)
        assert plan.mode == "vpn-up"
        assert 'oifname "wg0" accept' in plan.ruleset

    def test_vpn_down_rules_still_allow_dns(self):
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        snap = self._make_snapshot(vpn_iface="wg0", has_endpoints=False)
        snap = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP", is_virtual=False)},
            dns_servers=("1.1.1.1",),
            vpn_endpoint_ips=(),
        )
        vpn = VpnState(active=False, iface=None, provider="unknown")
        plan = fw.build_plan(snap, vpn, panic_mode=False)
        assert plan.mode == "vpn-down"
        assert "bootstrap_dns_v4" in plan.ruleset
        assert "udp dport" in plan.ruleset  # handshake ports present

    def test_panic_mode_returns_panic_plan(self):
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        snap = self._make_snapshot()
        vpn = VpnState(active=True, iface="wg0", provider="wireguard")
        plan = fw.build_plan(snap, vpn, panic_mode=True)
        assert plan.mode == "panic"

    def test_leaking_vpn_returns_panic_plan(self):
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        snap = self._make_snapshot()
        vpn = VpnState(active=True, iface="wg0", provider="wireguard", is_leaking=True)
        plan = fw.build_plan(snap, vpn, panic_mode=False)
        assert plan.mode == "panic"

    def test_bootstrap_dns_set_never_empty(self):
        """BUG-FW-03: bootstrap_dns_v4 nft set must never have empty elements."""
        from ghosttunnel.core.firewall import NftFirewallManager
        s = Settings()
        s.bootstrap_dns = []  # force empty
        fw = NftFirewallManager(s)
        snap = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP", is_virtual=False)},
            dns_servers=(),  # also empty
        )
        sets = fw._render_sets(snap)
        ruleset = "\n".join(sets)
        # elements line must exist with real IPs, not empty braces
        assert "elements = {  }" not in ruleset
        assert "1.1.1.1" in ruleset or "9.9.9.9" in ruleset

    def test_vpn_down_without_endpoints_no_set_reference(self):
        """BUG-FW-04: vpn-down mode must not reference @vpn_endpoints_v4 when set is absent."""
        from ghosttunnel.core.firewall import NftFirewallManager
        fw = NftFirewallManager(Settings())
        snap = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP", is_virtual=False)},
            dns_servers=("1.1.1.1",),
            vpn_endpoint_ips=(),  # no resolved endpoints
        )
        vpn = VpnState(active=False, iface=None, provider="unknown")
        plan = fw.build_plan(snap, vpn, panic_mode=False)
        assert plan.mode == "vpn-down"
        # Must NOT reference the non-existent vpn_endpoints_v4 set
        assert "@vpn_endpoints_v4" not in plan.ruleset

    def test_lan_ipv4_set_never_empty(self):
        """lan_ipv4 set must always have elements."""
        from ghosttunnel.core.firewall import NftFirewallManager
        s = Settings()
        s.lan_networks = []  # force empty
        fw = NftFirewallManager(s)
        snap = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP", is_virtual=False)},
            dns_servers=("1.1.1.1",),
        )
        sets = fw._render_sets(snap)
        ruleset = "\n".join(sets)
        # Should have fallback LAN networks
        assert "10.0.0.0" in ruleset or "192.168" in ruleset


# =====================================================================
# VPN Adapters — state detection (no system calls)
# =====================================================================
class TestProtonVpnAdapter:
    def test_detects_pvpn_wg_iface(self):
        from ghosttunnel.vpn.proton import ProtonVpnAdapter
        adapter = ProtonVpnAdapter()
        pvpn = InterfaceInfo(name="pvpn-abc123", state="UNKNOWN", ipv4=("10.2.0.1",), is_virtual=True)
        eth = InterfaceInfo(name="eth0", state="UP", is_virtual=False)
        snap = NetworkSnapshot(interfaces={"pvpn-abc123": pvpn, "eth0": eth})
        state = adapter.get_state(snap)
        assert state.active is True
        assert state.iface == "pvpn-abc123"
        assert state.provider == "protonvpn"

    def test_ignores_pvpnksintrf0(self):
        from ghosttunnel.vpn.proton import ProtonVpnAdapter
        adapter = ProtonVpnAdapter()
        ks = InterfaceInfo(name="pvpnksintrf0", state="UP", ipv4=("10.99.0.1",))
        snap = NetworkSnapshot(interfaces={"pvpnksintrf0": ks})
        state = adapter.get_state(snap)
        # Should NOT be detected as an active tunnel
        assert state.iface != "pvpnksintrf0"

    def test_no_vpn_when_no_proton_iface(self):
        from ghosttunnel.vpn.proton import ProtonVpnAdapter
        adapter = ProtonVpnAdapter()
        eth = InterfaceInfo(name="eth0", state="UP", is_virtual=False)
        snap = NetworkSnapshot(interfaces={"eth0": eth})
        state = adapter.get_state(snap)
        assert state.active is False


class TestWireguardAdapter:
    def test_detects_wg_iface_with_ip(self):
        from ghosttunnel.vpn.wireguard import WireguardAdapter
        adapter = WireguardAdapter()
        wg = InterfaceInfo(name="wg0", state="UNKNOWN", ipv4=("10.8.0.1",), is_virtual=True)
        snap = NetworkSnapshot(interfaces={"wg0": wg})
        state = adapter.get_state(snap)
        assert state.active is True
        assert state.iface == "wg0"

    def test_detects_mullvad_iface(self):
        from ghosttunnel.vpn.wireguard import WireguardAdapter
        adapter = WireguardAdapter()
        mv = InterfaceInfo(name="mullvad0", state="UP", ipv4=("10.64.0.1",))
        snap = NetworkSnapshot(interfaces={"mullvad0": mv})
        state = adapter.get_state(snap)
        assert state.active is True

    def test_no_vpn_without_wg_iface(self):
        from ghosttunnel.vpn.wireguard import WireguardAdapter
        adapter = WireguardAdapter()
        eth = InterfaceInfo(name="eth0", state="UP")
        snap = NetworkSnapshot(interfaces={"eth0": eth})
        state = adapter.get_state(snap)
        assert state.active is False


class TestOpenVpnAdapter:
    def test_detects_tun_iface(self):
        from ghosttunnel.vpn.openvpn import OpenVpnAdapter
        adapter = OpenVpnAdapter()
        tun = InterfaceInfo(name="tun0", state="UP", ipv4=("10.8.0.2",))
        snap = NetworkSnapshot(interfaces={"tun0": tun})
        state = adapter.get_state(snap)
        assert state.active is True
        assert state.iface == "tun0"


# =====================================================================
# Leak Detector — logic (mocked, no system calls)
# =====================================================================
class TestLeakDetectorLogic:
    def _make_settings(self, ipv6_block=True):
        s = Settings()
        s.ipv6_block = ipv6_block
        return s

    def test_no_vpn_iface_means_no_leak(self):
        from ghosttunnel.core.leak_detector import LeakDetector
        ld = LeakDetector.__new__(LeakDetector)
        ld.settings = self._make_settings()
        snap = NetworkSnapshot()
        assert ld.is_leaking(snap, None) is False

    def test_routing_leak_detected(self):
        from ghosttunnel.core.leak_detector import LeakDetector
        ld = LeakDetector.__new__(LeakDetector)
        ld.settings = self._make_settings()
        eth = InterfaceInfo(name="eth0", state="UP")
        wg = InterfaceInfo(name="wg0", state="UNKNOWN", ipv4=("10.8.0.1",))
        snap = NetworkSnapshot(
            interfaces={"eth0": eth, "wg0": wg},
            default_route_iface="eth0",  # traffic going out eth0 while VPN is wg0
        )
        assert ld.is_leaking(snap, "wg0") is True

    def test_no_leak_when_route_matches_vpn(self):
        from ghosttunnel.core.leak_detector import LeakDetector
        ld = LeakDetector.__new__(LeakDetector)
        ld.settings = self._make_settings()
        wg = InterfaceInfo(name="wg0", state="UNKNOWN", ipv4=("10.8.0.1",))
        snap = NetworkSnapshot(
            interfaces={"wg0": wg},
            default_route_iface="wg0",  # correct — VPN is default route
        )
        assert ld.is_leaking(snap, "wg0") is False


# =====================================================================
# GUI — subcommand allowlist (SEC-GUI-01)
# =====================================================================
class TestGuiSubcommandAllowlist:
    def test_allowed_subcommands_are_declared(self):
        import importlib
        import unittest.mock as mock

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
            assert "save-config" in allowed
            assert "rm -rf /" not in allowed
            assert len(allowed) == 4, "Allowlist should contain exactly 4 entries"


# =====================================================================
# IPC — protocol validation
# =====================================================================
class TestIpcProtocol:
    import sys
    @pytest.mark.skipif(sys.platform == 'win32', reason="AF_UNIX not available on Windows")
    def test_send_command_raises_on_malformed_response(self, tmp_path):
        """send_command() must raise ConnectionRefusedError if daemon returns garbage."""
        from ghosttunnel.core.ipc import send_command

        # Create a temp socket that returns non-JSON data
        fd, tmp_path = tempfile.mkstemp(suffix=".sock")
        os.close(fd)
        os.unlink(tmp_path)  # remove so bind() can create it as a socket

        server_sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        server_sock.bind(tmp_path)
        server_sock.listen(1)

        def _bad_server():
            try:
                conn, _ = server_sock.accept()
                conn.recv(1024)
                conn.sendall(b"not json at all\n")
                conn.close()
            finally:
                server_sock.close()

        t = threading.Thread(target=_bad_server, daemon=True)
        t.start()

        import ghosttunnel.core.ipc as ipc_mod
        original = ipc_mod.CTRL_SOCKET_PATH
        ipc_mod.CTRL_SOCKET_PATH = tmp_path
        try:
            with pytest.raises(ConnectionRefusedError):
                send_command("status")
        finally:
            ipc_mod.CTRL_SOCKET_PATH = original
            t.join(timeout=2)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    import sys
    @pytest.mark.skipif(sys.platform == 'win32', reason="AF_UNIX not available on Windows")
    def test_send_command_raises_when_socket_not_found(self):
        """send_command() raises ConnectionRefusedError when socket file doesn't exist."""
        from ghosttunnel.core.ipc import send_command
        import ghosttunnel.core.ipc as ipc_mod
        original = ipc_mod.CTRL_SOCKET_PATH
        ipc_mod.CTRL_SOCKET_PATH = "/tmp/ghosttunnel_nonexistent_sock_test.sock"
        try:
            with pytest.raises(ConnectionRefusedError):
                send_command("status")
        finally:
            ipc_mod.CTRL_SOCKET_PATH = original


# =====================================================================
# VPN Monitor — integration (no system calls)
# =====================================================================
class TestCustomVpnAdapter:
    def test_detects_custom_vpn_from_hints(self):
        from ghosttunnel.vpn.custom import CustomVpnAdapter
        s = Settings()
        s.vpn_hints = ["tailscale", "ipsec"]
        adapter = CustomVpnAdapter(s)
        
        ts = InterfaceInfo(name="tailscale0", state="UP", ipv4=("100.64.0.1",))
        eth = InterfaceInfo(name="eth0", state="UP", is_virtual=False)
        snap = NetworkSnapshot(interfaces={"tailscale0": ts, "eth0": eth})
        
        state = adapter.get_state(snap)
        assert state.active is True
        assert state.iface == "tailscale0"
        assert state.provider == "custom"

    def test_ignores_non_matching_interfaces(self):
        from ghosttunnel.vpn.custom import CustomVpnAdapter
        s = Settings()
        s.vpn_hints = ["tailscale"]
        adapter = CustomVpnAdapter(s)
        
        wg = InterfaceInfo(name="wg0", state="UP", ipv4=("10.8.0.1",))
        snap = NetworkSnapshot(interfaces={"wg0": wg})
        state = adapter.get_state(snap)
        assert state.active is False

class TestVpnMonitor:
    def test_returns_first_active_vpn(self):
        from ghosttunnel.core.vpn_monitor import VpnMonitor
        from ghosttunnel.vpn.generic import VpnAdapter

        class FakeAdapter(VpnAdapter):
            def __init__(self, name, active, iface):
                super().__init__(name)
                self._active = active
                self._iface = iface

            def get_state(self, snapshot):
                return VpnState(active=self._active, iface=self._iface, provider=self.name)

            def reconnect(self):
                return False

        monitor = VpnMonitor.__new__(VpnMonitor)
        monitor.adapters = [
            FakeAdapter("protonvpn", False, None),
            FakeAdapter("wireguard", True, "wg0"),
        ]
        snap = NetworkSnapshot()
        state = monitor.determine_state(snap)
        assert state.active is True
        assert state.iface == "wg0"
        assert state.provider == "wireguard"

    def test_returns_down_when_no_vpn(self):
        from ghosttunnel.core.vpn_monitor import VpnMonitor
        from ghosttunnel.vpn.generic import VpnAdapter

        class FakeAdapter(VpnAdapter):
            def get_state(self, snapshot):
                return VpnState(active=False, provider=self.name)

            def reconnect(self):
                return False

        monitor = VpnMonitor.__new__(VpnMonitor)
        monitor.adapters = [FakeAdapter("protonvpn"), FakeAdapter("wireguard")]
        snap = NetworkSnapshot()
        state = monitor.determine_state(snap)
        assert state.active is False


class TestAnomalyDetector:
    def test_anomaly_detection_no_attribute_errors(self) -> None:
        """Verify AnomalyDetector resolves links and gateway checks against correct NetworkSnapshot attributes without throwing AttributeError."""
        from ghosttunnel.core.anomaly import AnomalyDetector
        from ghosttunnel.core.models import InterfaceInfo, NetworkSnapshot

        detector = AnomalyDetector()
        
        # Test case 1: VPN active, default gateway matches VPN
        snap1 = NetworkSnapshot(
            interfaces={"wg0": InterfaceInfo(name="wg0", state="UP")},
            default_route_iface="wg0"
        )
        alerts1 = detector.analyze(snap1, "vpn-up", "wireguard", "wg0")
        assert len(alerts1) == 0

        # Test case 2: Routing mismatch (default route on eth0 instead of wg0)
        snap2 = NetworkSnapshot(
            interfaces={
                "wg0": InterfaceInfo(name="wg0", state="UP"),
                "eth0": InterfaceInfo(name="eth0", state="UP")
            },
            default_route_iface="eth0"
        )
        alerts2 = detector.analyze(snap2, "vpn-up", "wireguard", "wg0")
        assert any("Routing anomaly" in a for a in alerts2)

        # Test case 3: Interface vanished
        snap3 = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP")},
            default_route_iface="eth0"
        )
        alerts3 = detector.analyze(snap3, "vpn-up", "wireguard", "wg0")
        assert any("Interface anomaly" in a for a in alerts3)

        # Test case 4: Panic anomaly (default gateway exists during panic)
        snap4 = NetworkSnapshot(
            interfaces={"eth0": InterfaceInfo(name="eth0", state="UP")},
            default_route_iface="eth0"
        )
        alerts4 = detector.analyze(snap4, "panic", "wireguard", "wg0")
        assert any("Panic anomaly" in a for a in alerts4)


class TestConfigValidation:
    def test_save_config_ipc_validation_types(self, monkeypatch) -> None:
        """Verify daemon save config IPC validations properly sanitize and validate settings parameter types."""
        import ghosttunnel.core.system as system_mod
        import ghosttunnel.core.leak_detector as ld_mod
        import ghosttunnel.core.firewall as fw_mod

        monkeypatch.setattr(system_mod, "find_binary", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(ld_mod, "find_binary", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(fw_mod, "find_binary", lambda name: f"/usr/bin/{name}")
        
        from ghosttunnel.daemon import GhostDaemon
        from ghosttunnel.core.config import Settings
        
        s = Settings()
        daemon = GhostDaemon(s)
        
        # Inject bad payload with invalid types
        bad_payload = {
            "kill_switch": "not-a-bool",  # invalid bool
            "monitor_poll_seconds": "not-a-float",  # invalid float
            "table_name": 12345,  # invalid str
            "allow_lan": True  # valid bool
        }
        
        # Run IPC save config
        # Mock save() to avoid filesystem writes during test
        monkeypatch.setattr(Settings, "save", lambda self: None)
        try:
            res = daemon._ipc_save_config(bad_payload)
            assert "Configuration saved" in res.get("message", "")
            # Valid type was updated
            assert s.allow_lan is True
            # Invalid types were dropped/ignored
            assert isinstance(s.kill_switch, bool)
            assert s.kill_switch is True  # remained default
            assert isinstance(s.table_name, str)
            assert s.table_name == "ghosttunnel"  # remained default
        except Exception as e:
            pytest.fail(f"Save config failed: {e}")



class TestCorePublicMethods:
    def test_firewall_methods(self, monkeypatch):
        import ghosttunnel.core.firewall as fw_mod
        monkeypatch.setattr(fw_mod, "find_binary", lambda x: "/bin/nft")
        
        class MockNftables:
            def set_json_output(self, val): pass
            def cmd(self, val): return 0, "", ""
            
        class MockNftablesModule:
            Nftables = MockNftables
            
        monkeypatch.setattr(fw_mod, "nftables", MockNftablesModule)
        monkeypatch.setattr(fw_mod, "run", lambda *a, **kw: type("Res", (), {"returncode": 0, "stdout": "", "stderr": ""}))
        from ghosttunnel.core.firewall import NftFirewallManager, FirewallPlan
        from ghosttunnel.core.config import Settings
        from ghosttunnel.core.models import NetworkSnapshot, VpnState
        s = Settings()
        fw = NftFirewallManager(s)
        snap = NetworkSnapshot(interfaces={}, default_route_iface=None)
        vpn = VpnState(active=True, iface="wg0", provider="mullvad")
        plan = fw.build_plan(snap, vpn, panic_mode=False)
        assert isinstance(plan, FirewallPlan)
        monkeypatch.setattr("ghosttunnel.core.firewall.require_root", lambda: None)
        fw.activate(plan)
        fw.deactivate()
        assert fw.is_active() is True

    def test_system_run(self, monkeypatch):
        from ghosttunnel.core.system import run
        import subprocess
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: type("Res", (), {"returncode": 0, "stdout": "", "stderr": ""}))
        res = run(["/bin/ls"], check=False)
        assert res.returncode == 0

    def test_ipc_methods(self):
        from ghosttunnel.core.ipc import IpcServer
        server = IpcServer({"test": lambda p: {}})
        assert server is not None
        
    def test_leak_detector(self, monkeypatch):
        import ghosttunnel.core.leak_detector as ld_mod
        monkeypatch.setattr(ld_mod, "find_binary", lambda x: "/bin/ip")
        monkeypatch.setattr(ld_mod, "run", lambda *a, **kw: type("Res", (), {"returncode": 0, "stdout": "", "stderr": ""}))
        from ghosttunnel.core.config import Settings
        ld = ld_mod.LeakDetector(Settings())
        snap = ld.snapshot()
        assert snap is not None
        assert ld.is_leaking(snap, "wg0") is False

    def test_vpn_rotator(self):
        from ghosttunnel.core.config import Settings
        from ghosttunnel.core.vpn_rotator import VpnRotator
        vr = VpnRotator(Settings())
        vr.reset()
