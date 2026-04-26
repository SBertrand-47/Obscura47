"""Unit tests for Layer 1 sandbox enforcement."""

from __future__ import annotations

import os
import socket
import subprocess
import sys

import pytest

from src.agent.observatory import MemorySink, Observer
from src.agent.sandbox import (
    Sandbox,
    SandboxPolicy,
    SandboxViolation,
    current_session_id,
    set_current_session_id,
)


@pytest.fixture(autouse=True)
def _ensure_clean_sandbox():
    """Defensive teardown: never leak Layer 1 patches between tests."""
    yield
    while Sandbox.is_active():
        Sandbox.uninstall()


# ---------------------------------------------------------------------------
# SandboxPolicy validation.
# ---------------------------------------------------------------------------


def test_policy_rejects_unknown_network_mode():
    with pytest.raises(ValueError):
        SandboxPolicy(network="moon")


def test_policy_rejects_relative_fs_prefix():
    with pytest.raises(ValueError):
        SandboxPolicy(fs_read=("relative/path",))


def test_policy_rejects_non_tuple_relay_endpoints():
    with pytest.raises(TypeError):
        SandboxPolicy(relay_endpoints=[("127.0.0.1", 9047)])  # type: ignore[arg-type]


def test_policy_rejects_malformed_relay_endpoint():
    with pytest.raises(ValueError):
        SandboxPolicy(relay_endpoints=(("127.0.0.1",),))  # type: ignore[arg-type]


def test_policy_rejects_zero_rlimit():
    with pytest.raises(ValueError):
        SandboxPolicy(rlimit_as_bytes=0)


def test_policy_with_proxy_returns_updated_copy():
    p = SandboxPolicy()
    q = p.with_proxy("10.0.0.1", 9999)
    assert q.proxy_host == "10.0.0.1"
    assert q.proxy_port == 9999
    assert p.proxy_port == 0


def test_policy_with_relays_normalises_endpoints():
    p = SandboxPolicy().with_relays([("a", "1"), ("b", 2)])  # type: ignore[list-item]
    assert p.relay_endpoints == (("a", 1), ("b", 2))


# ---------------------------------------------------------------------------
# Install / uninstall lifecycle.
# ---------------------------------------------------------------------------


def test_install_uninstall_round_trip():
    policy = SandboxPolicy(fs_read=(os.path.realpath(os.getcwd()),))
    assert not Sandbox.is_active()
    Sandbox.install(policy)
    assert Sandbox.is_active()
    Sandbox.uninstall()
    assert not Sandbox.is_active()


def test_install_is_refcounted():
    policy = SandboxPolicy()
    Sandbox.install(policy)
    Sandbox.install(policy)
    Sandbox.install(policy)
    assert Sandbox.is_active()
    Sandbox.uninstall()
    assert Sandbox.is_active()
    Sandbox.uninstall()
    assert Sandbox.is_active()
    Sandbox.uninstall()
    assert not Sandbox.is_active()


def test_conflicting_policy_install_raises():
    Sandbox.install(SandboxPolicy(network="full"))
    try:
        with pytest.raises(RuntimeError):
            Sandbox.install(SandboxPolicy(network="none"))
    finally:
        Sandbox.uninstall()


def test_uninstall_below_zero_is_safe():
    Sandbox.uninstall()
    Sandbox.uninstall()
    assert not Sandbox.is_active()


def test_context_manager_restores_originals():
    original_open = open
    original_connect = socket.socket.connect
    with Sandbox(SandboxPolicy(network="full")):
        pass
    assert open is original_open
    assert socket.socket.connect is original_connect


# ---------------------------------------------------------------------------
# Filesystem enforcement.
# ---------------------------------------------------------------------------


def test_open_outside_allowlist_raises(tmp_path):
    inside = tmp_path / "ok.txt"
    inside.write_text("hi")
    outside = tmp_path.parent / "leaked.txt"

    policy = SandboxPolicy(fs_read=(str(tmp_path),), network="full")
    with Sandbox(policy):
        with open(inside) as f:
            assert f.read() == "hi"
        with pytest.raises(SandboxViolation) as excinfo:
            open(outside)
        assert excinfo.value.category == "fs_read"


def test_open_write_requires_fs_write_prefix(tmp_path):
    target = tmp_path / "out.log"
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(),
        network="full",
    )
    with Sandbox(policy):
        with pytest.raises(SandboxViolation) as excinfo:
            open(target, "w")
        assert excinfo.value.category == "fs_write"


def test_open_write_within_allowlist_succeeds(tmp_path):
    target = tmp_path / "out.log"
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="full",
    )
    with Sandbox(policy):
        with open(target, "w") as f:
            f.write("ok")
    assert target.read_text() == "ok"


def test_pathlib_open_is_guarded(tmp_path):
    from pathlib import Path

    leak = tmp_path.parent / "leak.txt"
    leak.write_text("nope")
    policy = SandboxPolicy(fs_read=(str(tmp_path),), network="full")
    with Sandbox(policy):
        with pytest.raises(SandboxViolation):
            Path(leak).open()


def test_os_remove_outside_allowlist_blocked(tmp_path):
    victim = tmp_path.parent / "victim.txt"
    victim.write_text("hi")
    try:
        policy = SandboxPolicy(
            fs_read=(str(tmp_path),),
            fs_write=(str(tmp_path),),
            network="full",
        )
        with Sandbox(policy):
            with pytest.raises(SandboxViolation):
                os.remove(victim)
        assert victim.exists()
    finally:
        if victim.exists():
            victim.unlink()


def test_os_open_writeable_blocked(tmp_path):
    victim = tmp_path.parent / "denied.bin"
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="full",
    )
    with Sandbox(policy):
        with pytest.raises(SandboxViolation):
            os.open(str(victim), os.O_WRONLY | os.O_CREAT)


# ---------------------------------------------------------------------------
# Network enforcement.
# ---------------------------------------------------------------------------


def test_network_none_blocks_all_outbound(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="none",
    )
    with Sandbox(policy):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(SandboxViolation) as excinfo:
                s.connect(("127.0.0.1", 1))
            assert excinfo.value.category == "network"
        finally:
            s.close()


def test_network_obscura_only_allows_loopback(tmp_path):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="obscura_only",
    )
    try:
        with Sandbox(policy):
            client = socket.create_connection(("127.0.0.1", port), timeout=1)
            client.close()
    finally:
        listener.close()


def test_network_obscura_only_allows_relay_endpoints(tmp_path):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="obscura_only",
        relay_endpoints=(("127.0.0.1", port),),
    )
    try:
        with Sandbox(policy):
            client = socket.create_connection(("127.0.0.1", port), timeout=1)
            client.close()
    finally:
        listener.close()


def test_network_obscura_only_blocks_unknown_host(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="obscura_only",
    )
    with Sandbox(policy):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with pytest.raises(SandboxViolation):
                s.connect(("203.0.113.5", 80))
        finally:
            s.close()


def test_network_full_does_not_check(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="full",
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        with Sandbox(policy):
            client = socket.create_connection(("127.0.0.1", port), timeout=1)
            client.close()
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# Subprocess enforcement.
# ---------------------------------------------------------------------------


def test_popen_blocked_when_disallowed(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="full",
    )
    with Sandbox(policy):
        with pytest.raises(SandboxViolation) as excinfo:
            subprocess.Popen(["true"])
        assert excinfo.value.category == "subprocess"


def test_os_system_blocked_when_disallowed(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="full",
    )
    with Sandbox(policy):
        with pytest.raises(SandboxViolation):
            os.system("true")


def test_subprocess_allowed_with_flag(tmp_path):
    policy = SandboxPolicy(
        fs_read=(str(tmp_path), "/usr", "/bin"),
        fs_write=(str(tmp_path),),
        network="full",
        allow_subprocess=True,
    )
    with Sandbox(policy):
        rc = subprocess.run(
            [sys.executable, "-c", "print(1)"],
            check=False, capture_output=True,
        ).returncode
    assert rc == 0


# ---------------------------------------------------------------------------
# Observer integration.
# ---------------------------------------------------------------------------


def test_violation_emits_observatory_event(tmp_path):
    sink = MemorySink()
    observer = Observer(actor="agent", sink=sink)
    policy = SandboxPolicy(fs_read=(str(tmp_path),), network="full")
    with Sandbox(policy, observer=observer):
        with pytest.raises(SandboxViolation):
            open(tmp_path.parent / "leak.txt")
    events = sink.events()
    kinds = [e.kind for e in events]
    assert "sandbox.violation" in kinds
    violation = next(e for e in events if e.kind == "sandbox.violation")
    assert violation.payload["category"] == "fs_read"
    assert "leak.txt" in violation.payload["detail"]


def test_violation_event_carries_session_id(tmp_path):
    sink = MemorySink()
    observer = Observer(actor="agent", sink=sink)
    policy = SandboxPolicy(fs_read=(str(tmp_path),), network="full")
    with Sandbox(policy, observer=observer):
        set_current_session_id("test-session-xyz")
        try:
            with pytest.raises(SandboxViolation):
                open(tmp_path.parent / "leak.txt")
        finally:
            set_current_session_id(None)
    [violation] = [e for e in sink.events() if e.kind == "sandbox.violation"]
    assert violation.session_id == "test-session-xyz"


# ---------------------------------------------------------------------------
# Per-thread context helpers.
# ---------------------------------------------------------------------------


def test_set_current_session_id_isolated_per_thread():
    import threading

    seen: dict[str, str | None] = {}

    def worker():
        seen["worker_default"] = current_session_id()
        set_current_session_id("worker")
        seen["worker_after"] = current_session_id()

    set_current_session_id("main")
    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen["worker_default"] is None
    assert seen["worker_after"] == "worker"
    assert current_session_id() == "main"
    set_current_session_id(None)


# ---------------------------------------------------------------------------
# RLIMIT.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="resource module unavailable on win32")
def test_rlimit_nofile_applied():
    import resource

    soft_before, hard_before = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = max(64, soft_before - 1)
    if target >= soft_before:
        pytest.skip("starting nofile limit too low to meaningfully cap")
    policy = SandboxPolicy(network="full", rlimit_nofile=target)
    Sandbox.install(policy)
    try:
        soft_after, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        assert soft_after == target
    finally:
        Sandbox.uninstall()
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_before, hard_before))
        except (ValueError, OSError):
            pass


# ---------------------------------------------------------------------------
# CLI policy parsing.
# ---------------------------------------------------------------------------


def test_policy_from_args_returns_none_without_flag():
    import argparse

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    parser = argparse.ArgumentParser()
    add_sandbox_arguments(parser)
    args = parser.parse_args([])
    assert policy_from_args(args) is None


def test_policy_from_args_parses_full_set(tmp_path):
    import argparse

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    parser = argparse.ArgumentParser()
    add_sandbox_arguments(parser)
    args = parser.parse_args([
        "--sandbox",
        "--sandbox-fs-read", str(tmp_path),
        "--sandbox-fs-write", str(tmp_path / "writable"),
        "--sandbox-network", "obscura_only",
        "--sandbox-allow-subprocess",
        "--sandbox-relay", "127.0.0.1:9050",
        "--sandbox-relay", "10.0.0.1:1234",
        "--sandbox-rlimit-as", "1073741824",
    ])
    (tmp_path / "writable").mkdir()
    policy = policy_from_args(args)
    assert policy is not None
    assert policy.fs_read == (str(tmp_path),)
    assert policy.fs_write == (str(tmp_path / "writable"),)
    assert policy.network == "obscura_only"
    assert policy.allow_subprocess is True
    assert policy.relay_endpoints == (("127.0.0.1", 9050), ("10.0.0.1", 1234))
    assert policy.rlimit_as_bytes == 1073741824


def test_policy_from_args_rejects_malformed_relay():
    import argparse

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    parser = argparse.ArgumentParser()
    add_sandbox_arguments(parser)
    args = parser.parse_args(["--sandbox", "--sandbox-relay", "not-a-host-port"])
    with pytest.raises(SystemExit):
        policy_from_args(args)


# ---------------------------------------------------------------------------
# macOS profile generator.
# ---------------------------------------------------------------------------


def test_macos_profile_contains_allow_clauses(tmp_path):
    from src.agent import _macos_sandbox

    policy = SandboxPolicy(
        fs_read=(str(tmp_path),),
        fs_write=(str(tmp_path),),
        network="obscura_only",
        proxy_host="127.0.0.1",
        proxy_port=9047,
        relay_endpoints=(("10.0.0.1", 1234),),
    )
    profile = _macos_sandbox.build_profile(policy)
    assert "(version 1)" in profile
    assert "(deny default)" in profile
    assert str(tmp_path) in profile
    assert "127.0.0.1:9047" in profile
    assert "10.0.0.1:1234" in profile


def test_macos_profile_full_network_is_unrestricted():
    from src.agent import _macos_sandbox

    profile = _macos_sandbox.build_profile(SandboxPolicy(network="full"))
    assert "(allow network*)" in profile


def test_macos_profile_none_network_omits_outbound():
    from src.agent import _macos_sandbox

    profile = _macos_sandbox.build_profile(SandboxPolicy(network="none"))
    assert "network-outbound" not in profile
    assert "(allow network*)" not in profile
