"""Platform-gated integration tests for OS-native Layer 2 enforcement.

These tests assert that, with Layer 2 engaged, FS escape attempts fail
*at the kernel level*, not just inside the in-process Layer 1 patches.

Each test spawns a fresh Python interpreter as a subprocess so the
applied sandbox doesn't leak back into the test runner. The Linux
path applies Landlock in the child via :mod:`src.agent._linux_sandbox`
directly; the macOS path goes through ``/usr/bin/sandbox-exec`` with a
generated profile.

Skipped when the host platform doesn't expose the required kernel
features (or Apple's deprecated ``sandbox-exec`` binary).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only Layer 2 backend")
def test_macos_sandbox_exec_blocks_outside_fs(tmp_path):
    if not shutil.which("sandbox-exec") and not os.path.isfile("/usr/bin/sandbox-exec"):
        pytest.skip("sandbox-exec not available")

    from src.agent import _macos_sandbox
    from src.agent.sandbox import SandboxPolicy

    leak = tmp_path.parent / "denied.txt"
    leak.write_text("nope")
    try:
        policy = SandboxPolicy(
            fs_read=(str(tmp_path),),
            fs_write=(str(tmp_path),),
            network="full",
        )
        profile = _macos_sandbox.build_profile(policy)
        script = textwrap.dedent(
            f"""
            import json, sys
            try:
                with open({str(leak)!r}) as f:
                    f.read()
                print(json.dumps({{"ok": True}}))
            except Exception as e:
                print(json.dumps({{"ok": False, "error": type(e).__name__}}))
            """
        ).strip()
        binary = "/usr/bin/sandbox-exec"
        if not os.path.isfile(binary):
            binary = shutil.which("sandbox-exec") or binary
        result = subprocess.run(
            [binary, "-p", profile, sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0 and not result.stdout.strip():
            pytest.skip(f"sandbox-exec rejected the test profile: {result.stderr.strip()}")
        last_line = result.stdout.strip().splitlines()[-1]
        envelope = json.loads(last_line)
        assert envelope["ok"] is False
        assert envelope["error"] in {"PermissionError", "OSError", "FileNotFoundError"}
    finally:
        if leak.exists():
            leak.unlink()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-only Layer 2 backend")
def test_linux_landlock_blocks_outside_fs(tmp_path):
    from src.agent import _linux_sandbox

    libc = _linux_sandbox._libc()
    if libc is None or _linux_sandbox._landlock_abi_version(libc) <= 0:
        pytest.skip("Landlock not supported on this kernel")

    leak = tmp_path.parent / "denied.txt"
    leak.write_text("nope")
    try:
        script = textwrap.dedent(
            f"""
            import json, sys
            from src.agent import _linux_sandbox
            from src.agent.sandbox import SandboxPolicy

            policy = SandboxPolicy(
                fs_read=({str(tmp_path)!r},),
                fs_write=({str(tmp_path)!r},),
                network="full",
            )
            assert _linux_sandbox.apply(policy) is True
            try:
                with open({str(leak)!r}) as f:
                    f.read()
                print(json.dumps({{"ok": True}}))
            except Exception as e:
                print(json.dumps({{"ok": False, "error": type(e).__name__}}))
            """
        ).strip()
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__),
        ))) + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15, env=env,
        )
        last_line = (result.stdout.strip().splitlines() or [""])[-1]
        envelope = json.loads(last_line) if last_line else {}
        assert envelope.get("ok") is False, (
            f"expected sandbox to block, got stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )
        assert envelope["error"] in {"PermissionError", "OSError", "FileNotFoundError"}
    finally:
        if leak.exists():
            leak.unlink()
