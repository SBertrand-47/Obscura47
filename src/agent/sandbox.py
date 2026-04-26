"""Host hardening for `.obscura` hidden-service runtimes.

Two layers of policy enforcement, sharing a single :class:`SandboxPolicy`:

* **Layer 1** (always available, this module). An in-process patcher
  that swaps a small set of standard-library entry points
  (``socket.socket.connect``, ``subprocess.Popen``, ``os.system``,
  ``builtins.open``, the FS-mutation helpers on :mod:`os`, and
  :class:`pathlib.Path` open) for guarded wrappers. Violations raise
  :class:`SandboxViolation` and emit a structured ``sandbox.violation``
  observability event when an :class:`Observer` is wired in. This is
  cooperative — Python is leaky enough that a determined attacker can
  bypass it — but it is enough to keep accidentally-misbehaving agent
  code on the rails and to make policy violations loud.

* **Layer 2** (best-effort, see :mod:`src.agent.sandboxed_runtime`).
  Wraps Layer 1 with kernel-level enforcement: a ``sandbox-exec``
  profile on macOS, ``seccomp-bpf`` + Landlock on Linux when
  available, no-op on Windows. Layer 2 always implies Layer 1.

Both layers consume a single :class:`SandboxPolicy` value. Construct
one with the FS prefixes, network mode, and resource caps that fit the
process you are about to host, hand it to :class:`AgentRuntime` (or to
the Layer 2 launcher), and the rest of the runtime stays unchanged.

Public framing: this is host-hardening machinery for `.obscura`
hidden-service operators. None of it is on the wire protocol.
"""

from __future__ import annotations

import builtins
import io
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Iterable

from src.utils.logger import get_logger

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)


__all__ = [
    "Sandbox",
    "SandboxPolicy",
    "SandboxViolation",
    "current_session_id",
    "set_current_session_id",
]


_NETWORK_MODES = frozenset({"none", "obscura_only", "full"})


class SandboxViolation(Exception):
    """Raised when a host action violates the active sandbox policy.

    ``category`` is one of ``"network"``, ``"fs_read"``, ``"fs_write"``,
    ``"subprocess"``. ``detail`` is a short human-readable description
    of what was blocked. The exception always carries enough context
    for an operator to figure out which policy clause needs widening.
    """

    def __init__(self, category: str, detail: str):
        super().__init__(f"[{category}] {detail}")
        self.category = category
        self.detail = detail


@dataclass(frozen=True)
class SandboxPolicy:
    """Declarative description of what a sandboxed host process may do.

    Attributes
    ----------
    fs_read / fs_write:
        Tuples of absolute path prefixes. A read or write is allowed
        only when the resolved path of the target starts with one of
        the entries (after symlink resolution via
        :func:`os.path.realpath`). Empty tuple means no access.
    network:
        ``"none"`` blocks every outbound socket connect,
        ``"obscura_only"`` allows loopback (127.0.0.1, ::1, localhost)
        + the configured proxy + entries in ``relay_endpoints``,
        ``"full"`` disables network checks entirely.
    allow_subprocess:
        When ``False``, :class:`subprocess.Popen`, :func:`os.system`,
        and :func:`os.popen` raise :class:`SandboxViolation`.
    proxy_host / proxy_port:
        Address of the local Obscura HTTP CONNECT proxy. Always
        whitelisted under ``"obscura_only"`` so :class:`AgentClient`
        keeps working.
    relay_endpoints:
        Static ``(host, port)`` pairs allowed under ``"obscura_only"``.
        Operators populate this with the relay set the runtime is
        bootstrapped against.
    rlimit_*:
        Best-effort resource caps applied with :func:`resource.setrlimit`
        on the first install. Silently skipped on platforms that don't
        expose :mod:`resource` (i.e. Windows).
    """

    fs_read: tuple[str, ...] = ()
    fs_write: tuple[str, ...] = ()
    network: str = "obscura_only"
    allow_subprocess: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 0
    relay_endpoints: tuple[tuple[str, int], ...] = ()
    rlimit_as_bytes: int | None = None
    rlimit_cpu_seconds: int | None = None
    rlimit_nofile: int | None = None

    def __post_init__(self) -> None:
        if self.network not in _NETWORK_MODES:
            raise ValueError(
                f"network must be one of {sorted(_NETWORK_MODES)}, got {self.network!r}"
            )
        for label, prefixes in (("fs_read", self.fs_read), ("fs_write", self.fs_write)):
            if not isinstance(prefixes, tuple):
                raise TypeError(f"{label} must be a tuple of strings")
            for p in prefixes:
                if not isinstance(p, str) or not p:
                    raise ValueError(f"{label} entries must be non-empty strings")
                if not os.path.isabs(p):
                    raise ValueError(f"{label} entries must be absolute paths: {p!r}")
        if not isinstance(self.relay_endpoints, tuple):
            raise TypeError("relay_endpoints must be a tuple")
        for ep in self.relay_endpoints:
            if (not isinstance(ep, tuple)
                    or len(ep) != 2
                    or not isinstance(ep[0], str)
                    or not isinstance(ep[1], int)):
                raise ValueError(
                    f"relay_endpoints entries must be (host: str, port: int): {ep!r}"
                )
        for label, value in (
            ("rlimit_as_bytes", self.rlimit_as_bytes),
            ("rlimit_cpu_seconds", self.rlimit_cpu_seconds),
            ("rlimit_nofile", self.rlimit_nofile),
        ):
            if value is not None and (not isinstance(value, int) or value <= 0):
                raise ValueError(f"{label} must be a positive int or None")

    def with_proxy(self, host: str, port: int) -> "SandboxPolicy":
        """Return a copy with ``proxy_host``/``proxy_port`` updated."""
        return replace(self, proxy_host=host, proxy_port=int(port))

    def with_relays(self, endpoints: Iterable[tuple[str, int]]) -> "SandboxPolicy":
        """Return a copy with ``relay_endpoints`` replaced."""
        eps = tuple((str(h), int(p)) for h, p in endpoints)
        return replace(self, relay_endpoints=eps)


# ---------------------------------------------------------------------------
# Per-thread context — lets violation events carry a session_id when the
# triggering call ran inside an HTTP handler.
# ---------------------------------------------------------------------------


_thread_ctx = threading.local()


def current_session_id() -> str | None:
    """Return the session id associated with the current thread, if any."""
    return getattr(_thread_ctx, "session_id", None)


def set_current_session_id(session_id: str | None) -> None:
    """Update the per-thread session id seen by sandbox violation events."""
    _thread_ctx.session_id = session_id


# ---------------------------------------------------------------------------
# Layer 1: in-process patcher.
# ---------------------------------------------------------------------------


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", ""})


class Sandbox:
    """Singleton-ish in-process enforcer for a :class:`SandboxPolicy`.

    Use as a context manager (``with Sandbox(policy): ...``) or via the
    explicit :meth:`install` / :meth:`uninstall` pair. Multiple enters
    are reference-counted so the runtime can install once at startup
    while the per-request dispatcher still re-enters the context for
    accounting; only the outermost enter actually patches.

    All instances share global state because monkey-patching itself is
    process-global. Concurrent installs with conflicting policies
    raise :class:`RuntimeError` to keep accidental nesting honest.
    """

    _global_lock = threading.RLock()
    _install_count = 0
    _active_policy: SandboxPolicy | None = None
    _active_observer: "Observer | None" = None
    _originals: dict[str, Any] = {}
    _allowed_endpoints: frozenset[tuple[str, int]] = frozenset()

    def __init__(
        self,
        policy: SandboxPolicy,
        *,
        observer: "Observer | None" = None,
    ):
        self.policy = policy
        self.observer = observer

    def __enter__(self) -> "Sandbox":
        Sandbox.install(self.policy, observer=self.observer)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ARG002
        Sandbox.uninstall()

    @classmethod
    def install(
        cls,
        policy: SandboxPolicy,
        *,
        observer: "Observer | None" = None,
    ) -> None:
        """Apply Layer 1 patches globally. Idempotent and ref-counted."""
        with cls._global_lock:
            if cls._install_count > 0:
                if cls._active_policy != policy:
                    raise RuntimeError(
                        "Sandbox already installed with a conflicting policy",
                    )
                cls._install_count += 1
                return
            cls._active_policy = policy
            cls._active_observer = observer
            cls._originals = _capture_originals()
            cls._allowed_endpoints = _expand_endpoints(policy)
            _apply_patches()
            _apply_rlimits(policy)
            cls._install_count = 1

    @classmethod
    def uninstall(cls) -> None:
        """Drop one ref. When the count reaches 0, restore originals."""
        with cls._global_lock:
            if cls._install_count == 0:
                return
            cls._install_count -= 1
            if cls._install_count > 0:
                return
            try:
                _restore_originals(cls._originals)
            finally:
                cls._originals = {}
                cls._active_policy = None
                cls._active_observer = None
                cls._allowed_endpoints = frozenset()

    @classmethod
    def is_active(cls) -> bool:
        with cls._global_lock:
            return cls._install_count > 0

    @classmethod
    def active_policy(cls) -> SandboxPolicy | None:
        with cls._global_lock:
            return cls._active_policy


# ---------------------------------------------------------------------------
# Patch capture / install / restore.
# ---------------------------------------------------------------------------


def _capture_originals() -> dict[str, Any]:
    return {
        "socket.connect": socket.socket.connect,
        "socket.connect_ex": socket.socket.connect_ex,
        "subprocess.Popen.__init__": subprocess.Popen.__init__,
        "os.system": os.system,
        "os.popen": os.popen,
        "builtins.open": builtins.open,
        "io.open": io.open,
        "os.open": os.open,
        "pathlib.Path.open": pathlib.Path.open,
        "os.remove": os.remove,
        "os.unlink": os.unlink,
        "os.rmdir": os.rmdir,
        "os.mkdir": os.mkdir,
        "os.makedirs": os.makedirs,
        "os.rename": os.rename,
        "os.replace": os.replace,
    }


def _apply_patches() -> None:
    socket.socket.connect = _guarded_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[assignment]
    subprocess.Popen.__init__ = _guarded_popen_init  # type: ignore[assignment]
    os.system = _guarded_os_system  # type: ignore[assignment]
    os.popen = _guarded_os_popen  # type: ignore[assignment]
    builtins.open = _guarded_open  # type: ignore[assignment]
    io.open = _guarded_open  # type: ignore[assignment]
    os.open = _guarded_os_open  # type: ignore[assignment]
    pathlib.Path.open = _guarded_path_open  # type: ignore[assignment]
    os.remove = _make_fs_mutator(_guarded_originals_key("os.remove"), check="write")  # type: ignore[assignment]
    os.unlink = _make_fs_mutator(_guarded_originals_key("os.unlink"), check="write")  # type: ignore[assignment]
    os.rmdir = _make_fs_mutator(_guarded_originals_key("os.rmdir"), check="write")  # type: ignore[assignment]
    os.mkdir = _make_fs_mutator(_guarded_originals_key("os.mkdir"), check="write")  # type: ignore[assignment]
    os.makedirs = _make_fs_mutator(_guarded_originals_key("os.makedirs"), check="write")  # type: ignore[assignment]
    os.rename = _make_fs_mutator2(_guarded_originals_key("os.rename"))  # type: ignore[assignment]
    os.replace = _make_fs_mutator2(_guarded_originals_key("os.replace"))  # type: ignore[assignment]


def _restore_originals(originals: dict[str, Any]) -> None:
    socket.socket.connect = originals["socket.connect"]  # type: ignore[assignment]
    socket.socket.connect_ex = originals["socket.connect_ex"]  # type: ignore[assignment]
    subprocess.Popen.__init__ = originals["subprocess.Popen.__init__"]  # type: ignore[assignment]
    os.system = originals["os.system"]  # type: ignore[assignment]
    os.popen = originals["os.popen"]  # type: ignore[assignment]
    builtins.open = originals["builtins.open"]  # type: ignore[assignment]
    io.open = originals["io.open"]  # type: ignore[assignment]
    os.open = originals["os.open"]  # type: ignore[assignment]
    pathlib.Path.open = originals["pathlib.Path.open"]  # type: ignore[assignment]
    os.remove = originals["os.remove"]  # type: ignore[assignment]
    os.unlink = originals["os.unlink"]  # type: ignore[assignment]
    os.rmdir = originals["os.rmdir"]  # type: ignore[assignment]
    os.mkdir = originals["os.mkdir"]  # type: ignore[assignment]
    os.makedirs = originals["os.makedirs"]  # type: ignore[assignment]
    os.rename = originals["os.rename"]  # type: ignore[assignment]
    os.replace = originals["os.replace"]  # type: ignore[assignment]


def _guarded_originals_key(key: str) -> str:
    return key


# ---------------------------------------------------------------------------
# Network guards.
# ---------------------------------------------------------------------------


def _guarded_connect(self: socket.socket, address: Any) -> Any:
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("socket.connect")
    if policy is None or orig is None:
        return socket.socket.connect(self, address)
    if not _network_allowed(self.family, address, policy):
        _record_violation("network", f"connect({address!r}) blocked by policy")
        raise SandboxViolation("network", f"outbound connect to {address!r} not permitted")
    return orig(self, address)


def _guarded_connect_ex(self: socket.socket, address: Any) -> int:
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("socket.connect_ex")
    if policy is None or orig is None:
        return socket.socket.connect_ex(self, address)
    if not _network_allowed(self.family, address, policy):
        _record_violation("network", f"connect_ex({address!r}) blocked by policy")
        raise SandboxViolation("network", f"outbound connect_ex to {address!r} not permitted")
    return orig(self, address)


def _network_allowed(family: int, address: Any, policy: SandboxPolicy) -> bool:
    if policy.network == "full":
        return True
    if family == getattr(socket, "AF_UNIX", -1):
        return False
    if not isinstance(address, tuple) or len(address) < 2:
        return False
    host, port = address[0], address[1]
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False
    if policy.network == "none":
        return False
    if not isinstance(host, str):
        return False
    if host in _LOOPBACK_HOSTS or host.startswith("127.") or host == "::1":
        return True
    if (host, port) in Sandbox._allowed_endpoints:
        return True
    return False


def _expand_endpoints(policy: SandboxPolicy) -> frozenset[tuple[str, int]]:
    """Pre-resolve hostnames in the policy to ``(ip, port)`` pairs.

    The patched ``socket.socket.connect`` only ever sees post-DNS
    addresses, so the allowlist must contain both the literal
    ``(host, port)`` written in the policy and any addresses
    :func:`socket.getaddrinfo` resolves the hostname to. Resolution
    failures are tolerated — an unresolvable hostname simply means
    that name won't be reachable, which is the safer default.
    """
    out: set[tuple[str, int]] = set()
    if policy.proxy_port:
        out.add((policy.proxy_host, int(policy.proxy_port)))
        for ip in _resolve(policy.proxy_host):
            out.add((ip, int(policy.proxy_port)))
    for host, port in policy.relay_endpoints:
        out.add((host, int(port)))
        for ip in _resolve(host):
            out.add((ip, int(port)))
    return frozenset(out)


def _resolve(host: str) -> list[str]:
    if not host:
        return []
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return []
    out: list[str] = []
    for info in infos:
        sa = info[4]
        if sa and isinstance(sa[0], str):
            out.append(sa[0])
    return out


# ---------------------------------------------------------------------------
# Subprocess guards.
# ---------------------------------------------------------------------------


def _guarded_popen_init(self, args, *a, **kw):  # type: ignore[no-untyped-def]
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("subprocess.Popen.__init__")
    if policy is not None and not policy.allow_subprocess:
        _record_violation("subprocess", f"Popen({args!r}) blocked by policy")
        raise SandboxViolation("subprocess", f"subprocess.Popen({args!r}) not permitted")
    return orig(self, args, *a, **kw)  # type: ignore[misc]


def _guarded_os_system(command: str) -> int:
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("os.system")
    if policy is not None and not policy.allow_subprocess:
        _record_violation("subprocess", f"os.system({command!r}) blocked by policy")
        raise SandboxViolation("subprocess", f"os.system({command!r}) not permitted")
    return orig(command)  # type: ignore[misc]


def _guarded_os_popen(*args: Any, **kwargs: Any) -> Any:
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("os.popen")
    if policy is not None and not policy.allow_subprocess:
        _record_violation("subprocess", f"os.popen{args!r} blocked by policy")
        raise SandboxViolation("subprocess", "os.popen not permitted")
    return orig(*args, **kwargs)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Filesystem guards.
# ---------------------------------------------------------------------------


def _guarded_open(file, mode="r", *args, **kwargs):  # type: ignore[no-untyped-def]
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("builtins.open")
    if policy is None or orig is None:
        return builtins.open(file, mode, *args, **kwargs)
    if isinstance(file, int):
        return orig(file, mode, *args, **kwargs)
    is_write = any(c in mode for c in "wax+")
    abspath = _resolve_path(file)
    if abspath is None:
        return orig(file, mode, *args, **kwargs)
    if is_write:
        if not _path_allowed(abspath, policy.fs_write):
            _record_violation("fs_write", f"open({abspath!r}, {mode!r}) blocked")
            raise SandboxViolation("fs_write", f"write to {abspath} not permitted")
    if not _path_allowed(abspath, policy.fs_read):
        _record_violation("fs_read", f"open({abspath!r}, {mode!r}) blocked")
        raise SandboxViolation("fs_read", f"read of {abspath} not permitted")
    return orig(file, mode, *args, **kwargs)


def _guarded_os_open(path, flags, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
    policy = Sandbox._active_policy
    orig = Sandbox._originals.get("os.open")
    if policy is None or orig is None:
        return os.open(path, flags, mode, dir_fd=dir_fd)
    is_write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC))
    abspath = _resolve_path(path)
    if abspath is None:
        return orig(path, flags, mode, dir_fd=dir_fd)
    if is_write and not _path_allowed(abspath, policy.fs_write):
        _record_violation("fs_write", f"os.open({abspath!r}) blocked")
        raise SandboxViolation("fs_write", f"write to {abspath} not permitted")
    if not _path_allowed(abspath, policy.fs_read):
        _record_violation("fs_read", f"os.open({abspath!r}) blocked")
        raise SandboxViolation("fs_read", f"read of {abspath} not permitted")
    return orig(path, flags, mode, dir_fd=dir_fd)


def _guarded_path_open(self: pathlib.Path, mode="r", *args, **kwargs):  # type: ignore[no-untyped-def]
    return _guarded_open(str(self), mode, *args, **kwargs)


def _make_fs_mutator(key: str, *, check: str) -> Callable[..., Any]:
    def _wrap(path: Any, *a: Any, **kw: Any) -> Any:
        policy = Sandbox._active_policy
        orig = Sandbox._originals.get(key)
        if policy is None or orig is None:
            return orig(path, *a, **kw)  # type: ignore[misc]
        abspath = _resolve_path(path)
        if abspath is not None and not _path_allowed(abspath, policy.fs_write):
            _record_violation("fs_write", f"{key}({abspath!r}) blocked")
            raise SandboxViolation("fs_write", f"{check} on {abspath} not permitted")
        return orig(path, *a, **kw)  # type: ignore[misc]
    return _wrap


def _make_fs_mutator2(key: str) -> Callable[..., Any]:
    def _wrap(src: Any, dst: Any, *a: Any, **kw: Any) -> Any:
        policy = Sandbox._active_policy
        orig = Sandbox._originals.get(key)
        if policy is None or orig is None:
            return orig(src, dst, *a, **kw)  # type: ignore[misc]
        for label, p in (("src", src), ("dst", dst)):
            abspath = _resolve_path(p)
            if abspath is None:
                continue
            if not _path_allowed(abspath, policy.fs_write):
                _record_violation("fs_write", f"{key}({label}={abspath!r}) blocked")
                raise SandboxViolation(
                    "fs_write",
                    f"rename/replace involving {abspath} not permitted",
                )
        return orig(src, dst, *a, **kw)  # type: ignore[misc]
    return _wrap


def _resolve_path(p: Any) -> str | None:
    """Best-effort resolution of ``p`` to an absolute, symlink-free path.

    Returns ``None`` for non-path-like inputs so the patched call falls
    through to the original implementation, which will then raise the
    natural ``TypeError``.
    """
    try:
        raw = os.fspath(p)
    except TypeError:
        return None
    try:
        return os.path.realpath(os.path.abspath(raw))
    except (OSError, ValueError):
        try:
            return os.path.abspath(raw)
        except Exception:
            return None


def _path_allowed(abspath: str, prefixes: tuple[str, ...]) -> bool:
    if not prefixes:
        return False
    norm = os.path.normpath(abspath)
    for prefix in prefixes:
        canon = os.path.normpath(os.path.realpath(prefix))
        if norm == canon:
            return True
        if norm.startswith(canon.rstrip(os.sep) + os.sep):
            return True
    return False


# ---------------------------------------------------------------------------
# Resource limits.
# ---------------------------------------------------------------------------


def _apply_rlimits(policy: SandboxPolicy) -> None:
    try:
        import resource  # noqa: PLC0415  -- platform-dependent
    except ImportError:
        return
    pairs = [
        ("RLIMIT_AS", policy.rlimit_as_bytes),
        ("RLIMIT_CPU", policy.rlimit_cpu_seconds),
        ("RLIMIT_NOFILE", policy.rlimit_nofile),
    ]
    for name, value in pairs:
        if value is None:
            continue
        const = getattr(resource, name, None)
        if const is None:
            continue
        try:
            soft, hard = resource.getrlimit(const)
            new_soft = min(value, hard) if hard != resource.RLIM_INFINITY else value
            new_hard = hard if hard != resource.RLIM_INFINITY else value
            resource.setrlimit(const, (new_soft, new_hard))
        except (ValueError, OSError) as e:
            log.warning("sandbox: setrlimit(%s, %s) failed: %s", name, value, e)


# ---------------------------------------------------------------------------
# Violation reporting.
# ---------------------------------------------------------------------------


def _record_violation(category: str, detail: str) -> None:
    observer = Sandbox._active_observer
    if observer is None:
        log.warning("sandbox.violation [%s] %s", category, detail)
        return
    try:
        observer.emit(
            "sandbox.violation",
            session_id=current_session_id(),
            category=category,
            detail=detail,
            ts=time.time(),
        )
    except Exception:
        log.exception("sandbox: failed to emit violation event")
