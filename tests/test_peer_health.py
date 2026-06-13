"""Unit tests for the ws_port reachability diagnosis and self-healing helpers
added to peer_health: registry-authoritative verdict, firewall command
planning, and consent-gated auto-open.
"""

import subprocess

from src.core import peer_health as ph
from src.core import internet_discovery as net_mod


# --------------------------------------------------------------------------
# _auto_open_enabled
# --------------------------------------------------------------------------

def test_auto_open_disabled_by_default(monkeypatch):
    monkeypatch.delenv("OBSCURA_AUTO_OPEN_PORTS", raising=False)
    assert ph._auto_open_enabled() is False


def test_auto_open_accepts_truthy_spellings(monkeypatch):
    for val in ("1", "true", "YES", "On", " true "):
        monkeypatch.setenv("OBSCURA_AUTO_OPEN_PORTS", val)
        assert ph._auto_open_enabled() is True
    for val in ("0", "false", "no", ""):
        monkeypatch.setenv("OBSCURA_AUTO_OPEN_PORTS", val)
        assert ph._auto_open_enabled() is False


# --------------------------------------------------------------------------
# _firewall_open_plan
# --------------------------------------------------------------------------

def _which_only(*present):
    """Return a fake shutil.which that only knows about ``present`` tools."""
    return lambda name: (f"/usr/bin/{name}" if name in present else None)


def test_firewall_plan_prefers_ufw(monkeypatch):
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(shutil, "which", _which_only("ufw", "iptables"))
    desc, argv = ph._firewall_open_plan(9001)
    assert desc == "sudo ufw allow 9001/tcp"
    assert argv == ["ufw", "allow", "9001/tcp"]


def test_firewall_plan_falls_back_to_iptables(monkeypatch):
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(shutil, "which", _which_only("iptables"))
    desc, argv = ph._firewall_open_plan(9001)
    assert argv[0] == "iptables" and "9001" in argv
    assert "9001" in desc


def test_firewall_plan_windows_uses_netsh(monkeypatch):
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Windows")
    # which should be irrelevant on Windows; ensure netsh path is taken first.
    monkeypatch.setattr(shutil, "which", _which_only())
    desc, argv = ph._firewall_open_plan(443)
    assert argv[0] == "netsh"
    assert "localport=443" in argv


def test_firewall_plan_none_when_no_tool(monkeypatch):
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(shutil, "which", _which_only())
    assert ph._firewall_open_plan(9001) == (None, None)


# --------------------------------------------------------------------------
# _registry_ws_masked
# --------------------------------------------------------------------------

def test_registry_masked_when_entry_present_but_ws_port_dropped(monkeypatch):
    monkeypatch.setattr(net_mod, "_my_public_ip", "203.0.113.5")
    monkeypatch.setattr(
        net_mod, "fetch_peers_from_registry",
        lambda role_filter=None: [{"role": "relay", "host": "203.0.113.5"}],
    )
    # We appear in /peers but our ws_port has been masked -> unreachable.
    assert ph._registry_ws_masked("relay", "203.0.113.5", 9001) is True


def test_registry_reachable_when_ws_port_still_advertised(monkeypatch):
    monkeypatch.setattr(net_mod, "_my_public_ip", "203.0.113.5")
    monkeypatch.setattr(
        net_mod, "fetch_peers_from_registry",
        lambda role_filter=None: [
            {"role": "relay", "host": "203.0.113.5", "ws_port": 9001},
        ],
    )
    assert ph._registry_ws_masked("relay", "203.0.113.5", 9001) is False


def test_registry_none_when_not_listed(monkeypatch):
    monkeypatch.setattr(net_mod, "_my_public_ip", "203.0.113.5")
    monkeypatch.setattr(
        net_mod, "fetch_peers_from_registry",
        lambda role_filter=None: [{"role": "relay", "host": "198.51.100.9", "ws_port": 9001}],
    )
    assert ph._registry_ws_masked("relay", "203.0.113.5", 9001) is None


def test_registry_none_when_registry_unavailable(monkeypatch):
    def boom(role_filter=None):
        raise RuntimeError("registry down")
    monkeypatch.setattr(net_mod, "fetch_peers_from_registry", boom)
    assert ph._registry_ws_masked("relay", "203.0.113.5", 9001) is None


def test_registry_ignores_malformed_ws_port(monkeypatch):
    monkeypatch.setattr(net_mod, "_my_public_ip", "203.0.113.5")
    monkeypatch.setattr(
        net_mod, "fetch_peers_from_registry",
        lambda role_filter=None: [
            {"role": "relay", "host": "203.0.113.5", "ws_port": "not-an-int"},
        ],
    )
    # Malformed entry can't prove reachability -> treated as masked.
    assert ph._registry_ws_masked("relay", "203.0.113.5", 9001) is True


# --------------------------------------------------------------------------
# _try_open_firewall
# --------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_try_open_firewall_success(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0)  # simulate root: exercise the command path, not the privilege gate
    monkeypatch.setattr(shutil, "which", _which_only("ufw"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _FakeProc(0))
    ok, msg = ph._try_open_firewall(9001)
    assert ok is True
    assert "ufw allow 9001/tcp" in msg


def test_try_open_firewall_reports_command_failure(monkeypatch):
    import os
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0)  # simulate root: exercise the command path, not the privilege gate
    monkeypatch.setattr(shutil, "which", _which_only("ufw"))
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: _FakeProc(1, stderr="permission denied"))
    ok, msg = ph._try_open_firewall(9001)
    assert ok is False
    assert "permission denied" in msg


def test_try_open_firewall_no_tool(monkeypatch):
    import shutil
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr(shutil, "which", _which_only())
    ok, msg = ph._try_open_firewall(9001)
    assert ok is False
    assert "no supported firewall tool" in msg


# --------------------------------------------------------------------------
# diagnose_ws_reachability
# --------------------------------------------------------------------------

def test_diagnose_prefers_registry_unreachable(monkeypatch):
    monkeypatch.setattr(ph, "_registry_ws_masked", lambda *a, **k: True)
    monkeypatch.setattr("platform.system", lambda: "Linux")
    import shutil
    monkeypatch.setattr(shutil, "which", _which_only("ufw"))
    v = ph.diagnose_ws_reachability("relay", "203.0.113.5", 9001)
    assert v["reachable"] is False
    assert v["source"] == "registry"
    assert v["fix_command"] == "sudo ufw allow 9001/tcp"


def test_diagnose_prefers_registry_reachable(monkeypatch):
    monkeypatch.setattr(ph, "_registry_ws_masked", lambda *a, **k: False)
    v = ph.diagnose_ws_reachability("relay", "203.0.113.5", 9001)
    assert v["reachable"] is True
    assert v["source"] == "registry"


def test_diagnose_falls_back_to_local_probe(monkeypatch):
    monkeypatch.setattr(ph, "_registry_ws_masked", lambda *a, **k: None)
    monkeypatch.setattr(ph, "probe_tcp", lambda host, port, timeout=3.0: (True, "ok"))
    v = ph.diagnose_ws_reachability("relay", "203.0.113.5", 9001)
    assert v["reachable"] is True
    assert v["source"] == "local"


def test_diagnose_local_probe_failure_carries_reason(monkeypatch):
    monkeypatch.setattr(ph, "_registry_ws_masked", lambda *a, **k: None)
    monkeypatch.setattr(
        ph, "probe_tcp", lambda host, port, timeout=3.0: (False, "ConnectionRefused"))
    v = ph.diagnose_ws_reachability("relay", "203.0.113.5", 9001)
    assert v["reachable"] is False
    assert v["source"] == "local"
    assert "ConnectionRefused" in v["detail"]
