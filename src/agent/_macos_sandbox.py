"""macOS Layer 2 sandbox: ``/usr/bin/sandbox-exec`` profile generator.

Translates a :class:`~src.agent.sandbox.SandboxPolicy` into the
``sandbox-exec`` policy DSL and re-execs the current Python process
under the resulting profile. Once the kernel-level sandbox is engaged,
forbidden file or network operations fail at the syscall layer
regardless of what the in-process Layer 1 patches catch.

Apple has formally deprecated the ``sandbox-exec`` binary but it has
shipped on every macOS release through 2026 and is still the only
no-extra-dependency way to apply a system-level sandbox to an
arbitrary subprocess. This module degrades gracefully when the binary
is missing (or the platform isn't macOS): :func:`apply` returns
``False`` and the caller falls back to Layer 1 only.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import TYPE_CHECKING

from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.sandbox import SandboxPolicy

log = get_logger(__name__)


SANDBOX_EXEC_BINARY = "/usr/bin/sandbox-exec"
_REENTRY_ENV_FLAG = "OBSCURA_SANDBOX_LAYER2_ACTIVE"


def is_supported() -> bool:
    """Return True when ``sandbox-exec`` is present on this host."""
    if sys.platform != "darwin":
        return False
    return os.path.isfile(SANDBOX_EXEC_BINARY) and os.access(
        SANDBOX_EXEC_BINARY, os.X_OK,
    ) or shutil.which("sandbox-exec") is not None


def already_applied() -> bool:
    """Return True when the current process is already running under Layer 2."""
    return os.environ.get(_REENTRY_ENV_FLAG) == "1"


def build_profile(policy: "SandboxPolicy") -> str:
    """Render a :class:`SandboxPolicy` as a sandbox-exec policy string.

    The policy text uses the ``(version 1)`` SBPL dialect that ships
    with macOS. We start from a deny-all baseline, then explicitly
    allow:

    * ``process-fork`` and ``process-exec`` of the current Python
      interpreter (otherwise the wrapped process can't run).
    * Read of system libraries needed for Python startup
      (``/usr/lib``, ``/System``, ``/Library``, the interpreter's
      ``sys.prefix`` tree).
    * The FS read/write prefixes named in the policy.
    * Network outbound to allowed endpoints (full when
      ``network="full"``; specific subnet rules when
      ``network="obscura_only"``; nothing when ``network="none"``).
    """
    lines: list[str] = [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        "(allow process-exec)",
        "(allow signal)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow ipc-posix-shm)",
        "(allow file-read-metadata)",
        # Python's startup walks the path from "/" to find dylibs and
        # the dyld cache; it aborts during interpreter init if the
        # root entry isn't readable. Granting only the literal root
        # node leaves child directories under deny-by-default unless
        # they're explicitly listed below.
        "(allow file-read* (literal \"/\"))",
        "(allow file-read* (subpath \"/usr/lib\"))",
        "(allow file-read* (subpath \"/usr/share\"))",
        "(allow file-read* (subpath \"/System\"))",
        "(allow file-read* (subpath \"/Library\"))",
        "(allow file-read* (subpath \"/private/etc\"))",
        "(allow file-read* (subpath \"/private/var/db/timezone\"))",
        "(allow file-read* (subpath \"/dev\"))",
        "(allow file-write* (literal \"/dev/null\"))",
        "(allow file-write* (literal \"/dev/dtracehelper\"))",
    ]

    seen: set[str] = set()

    def _allow_subpath(path: str) -> None:
        norm = os.path.normpath(path)
        if not norm or norm == "/" or norm in seen:
            return
        seen.add(norm)
        lines.append(f"(allow file-read* (subpath \"{_quote(norm)}\"))")

    _allow_subpath(sys.prefix)
    _allow_subpath(getattr(sys, "base_prefix", sys.prefix))
    # ``sys.executable`` is often a wrapper that dyld-resolves into a
    # framework path under /opt/homebrew/Cellar or /Library/Frameworks.
    # Walk both the symlink target and its realpath so the loader can
    # find the Python.framework wherever Homebrew/pyenv put it.
    exe = os.path.normpath(sys.executable)
    _allow_subpath(os.path.dirname(exe))
    real_exe = os.path.realpath(exe)
    _allow_subpath(os.path.dirname(real_exe))
    # Common Homebrew install root; harmless when absent.
    _allow_subpath("/opt/homebrew")
    _allow_subpath(os.path.realpath(os.getcwd()))

    for prefix in policy.fs_read:
        lines.append(f"(allow file-read* (subpath \"{_quote(prefix)}\"))")
    for prefix in policy.fs_write:
        lines.append(f"(allow file-write* (subpath \"{_quote(prefix)}\"))")
        lines.append(f"(allow file-read* (subpath \"{_quote(prefix)}\"))")

    if policy.network == "full":
        lines.append("(allow network*)")
    elif policy.network == "obscura_only":
        lines.append("(allow network-bind (local ip))")
        lines.append("(allow network-outbound (remote ip \"localhost:*\"))")
        lines.append("(allow network-outbound (remote ip \"127.0.0.1:*\"))")
        lines.append("(allow network-outbound (remote ip \"::1:*\"))")
        if policy.proxy_port:
            lines.append(
                f"(allow network-outbound (remote ip "
                f"\"{_quote(policy.proxy_host)}:{int(policy.proxy_port)}\"))"
            )
        for host, port in policy.relay_endpoints:
            lines.append(
                f"(allow network-outbound (remote ip "
                f"\"{_quote(host)}:{int(port)}\"))"
            )
    return "\n".join(lines) + "\n"


def apply(policy: "SandboxPolicy") -> bool:
    """Re-exec the current process under ``sandbox-exec``.

    Does nothing and returns ``False`` when:

    * we're not on macOS,
    * ``sandbox-exec`` is missing,
    * we've already been re-execed once (idempotent guard).

    Otherwise this function does **not return** on success — it
    replaces the current process image with the sandboxed one. On
    failure it logs and returns ``False`` so the caller can fall back
    to Layer 1 only.
    """
    if already_applied():
        return True
    if not is_supported():
        log.info("macOS sandbox-exec not available; skipping Layer 2")
        return False
    binary = SANDBOX_EXEC_BINARY if os.path.isfile(SANDBOX_EXEC_BINARY) else (
        shutil.which("sandbox-exec") or SANDBOX_EXEC_BINARY
    )
    profile = build_profile(policy)
    env = dict(os.environ)
    env[_REENTRY_ENV_FLAG] = "1"
    argv = [binary, "-p", profile, sys.executable, *sys.argv]
    log.info("re-execing under macOS sandbox-exec (%d byte profile)", len(profile))
    try:
        os.execvpe(binary, argv, env)
    except OSError as e:
        log.error("sandbox-exec re-exec failed: %s", e)
        return False
    return False  # unreachable


def _quote(value: str) -> str:
    """Escape a path/host literal for embedding inside sandbox-exec strings."""
    return value.replace("\\", "\\\\").replace("\"", "\\\"")
