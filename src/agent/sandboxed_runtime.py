"""Layer 2 launcher: run an :class:`AgentRuntime` under OS-native sandboxing.

Picks the right kernel-level backend for the host platform, applies
it, and then hands off to the same code path :mod:`src.agent.__main__`
uses. Layer 1 (the in-process Python patcher) is always engaged on
top — Layer 2 protects against escapes that would defeat Layer 1.

Backends:

* macOS — re-exec under :program:`/usr/bin/sandbox-exec` with a
  generated profile.
* Linux — apply Landlock + ``PR_SET_NO_NEW_PRIVS`` in-process.
* Anything else — log a warning and continue with Layer 1 only.

CLI flags mirror :mod:`src.agent.__main__` plus the
``--sandbox-*`` family that builds the :class:`SandboxPolicy`.
"""

from __future__ import annotations

import argparse
import sys

from src.agent.runtime import AgentRuntime
from src.agent.sandbox import SandboxPolicy
from src.utils.logger import get_logger

log = get_logger(__name__)


def add_sandbox_arguments(parser: argparse.ArgumentParser) -> None:
    """Attach the standard ``--sandbox-*`` flag set to ``parser``.

    Shared by every agent CLI so policy syntax is consistent across
    binaries. Does not enable sandboxing on its own — the caller is
    responsible for passing ``policy=`` into :class:`AgentRuntime`.
    """
    group = parser.add_argument_group("sandbox")
    group.add_argument(
        "--sandbox", action="store_true",
        help="enable Layer 1 sandbox (FS allowlist, network policy, no subprocess)",
    )
    group.add_argument(
        "--sandbox-fs-read", action="append", default=[],
        metavar="PATH",
        help="absolute path prefix the sandbox may read; repeat for multiple",
    )
    group.add_argument(
        "--sandbox-fs-write", action="append", default=[],
        metavar="PATH",
        help="absolute path prefix the sandbox may write; repeat for multiple",
    )
    group.add_argument(
        "--sandbox-network", choices=("none", "obscura_only", "full"),
        default="obscura_only",
        help="outbound network policy when --sandbox is set (default: obscura_only)",
    )
    group.add_argument(
        "--sandbox-allow-subprocess", action="store_true",
        help="permit subprocess.Popen / os.system from sandboxed code",
    )
    group.add_argument(
        "--sandbox-relay", action="append", default=[],
        metavar="HOST:PORT",
        help="extra (host, port) endpoint to allow under obscura_only; repeatable",
    )
    group.add_argument(
        "--sandbox-rlimit-as", type=int, default=None,
        metavar="BYTES",
        help="virtual memory cap (RLIMIT_AS) applied at install",
    )
    group.add_argument(
        "--sandbox-rlimit-cpu", type=int, default=None,
        metavar="SECONDS",
        help="CPU time cap (RLIMIT_CPU) applied at install",
    )
    group.add_argument(
        "--sandbox-rlimit-nofile", type=int, default=None,
        metavar="N",
        help="open-file-descriptor cap (RLIMIT_NOFILE) applied at install",
    )


def policy_from_args(args: argparse.Namespace) -> SandboxPolicy | None:
    """Build a :class:`SandboxPolicy` from the parsed CLI namespace.

    Returns ``None`` when ``--sandbox`` was not supplied. Raises
    :class:`SystemExit` with a useful message on malformed flags so
    operators don't get a stack trace.
    """
    if not getattr(args, "sandbox", False):
        return None

    relays: list[tuple[str, int]] = []
    for spec in args.sandbox_relay or ():
        host, _, port_str = spec.rpartition(":")
        if not host or not port_str:
            raise SystemExit(
                f"--sandbox-relay must be HOST:PORT, got {spec!r}"
            )
        try:
            port = int(port_str)
        except ValueError:
            raise SystemExit(
                f"--sandbox-relay port must be an integer, got {port_str!r}"
            )
        relays.append((host, port))

    try:
        return SandboxPolicy(
            fs_read=tuple(args.sandbox_fs_read or ()),
            fs_write=tuple(args.sandbox_fs_write or ()),
            network=args.sandbox_network,
            allow_subprocess=bool(args.sandbox_allow_subprocess),
            relay_endpoints=tuple(relays),
            rlimit_as_bytes=args.sandbox_rlimit_as,
            rlimit_cpu_seconds=args.sandbox_rlimit_cpu,
            rlimit_nofile=args.sandbox_rlimit_nofile,
        )
    except (TypeError, ValueError) as e:
        raise SystemExit(f"invalid sandbox policy: {e}")


def apply_layer2(policy: SandboxPolicy) -> bool:
    """Engage the OS-native sandbox for the current platform.

    Returns ``True`` on best-effort success (which on macOS means a
    successful re-exec — control does not return to the original
    process), ``False`` when the platform has no Layer 2 backend or
    activation failed.
    """
    if sys.platform == "darwin":
        from src.agent import _macos_sandbox

        return _macos_sandbox.apply(policy)
    if sys.platform.startswith("linux"):
        from src.agent import _linux_sandbox

        return _linux_sandbox.apply(policy)
    log.info("Layer 2 not supported on %s; running with Layer 1 only", sys.platform)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.agent.sandboxed_runtime",
        description=(
            "Run an AgentRuntime under OS-native sandboxing. The launcher "
            "applies Landlock (Linux) or sandbox-exec (macOS) before "
            "starting the runtime; Layer 1 enforcement is always on top."
        ),
    )
    parser.add_argument(
        "--name", default="agent",
        help="display name surfaced in the default /info route",
    )
    parser.add_argument(
        "--key", default="agent_service.pem",
        help="path to the service ECC keypair (PEM); created if missing",
    )
    parser.add_argument(
        "--bind", default="127.0.0.1",
        help="local interface for the HTTP server (default 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=0,
        help="local port for the HTTP server (default: pick a free port)",
    )
    parser.add_argument(
        "--app", default=None,
        help="optional MODULE:ATTR pointing at an AgentApp or factory",
    )
    parser.add_argument(
        "--observatory", default=None,
        help="optional .obscura address of a collector to forward events to",
    )
    parser.add_argument(
        "--observatory-jsonl", default=None,
        help="optional local JSONL path for observability events",
    )
    add_sandbox_arguments(parser)
    args = parser.parse_args(argv)

    policy = policy_from_args(args)
    if policy is None:
        print(
            "[sandboxed_runtime] --sandbox is required; use python -m src.agent "
            "for unsandboxed runs",
            file=sys.stderr,
        )
        return 2

    apply_layer2(policy)

    from src.agent.__main__ import _load_app
    from src.agent.observatory import build_observer_from_flags

    observer = build_observer_from_flags(
        actor=args.name,
        remote_addr=args.observatory,
        jsonl_path=args.observatory_jsonl,
    )

    app = _load_app(args.app) if args.app else None
    runtime = AgentRuntime(
        name=args.name,
        key_path=args.key,
        app=app,
        bind_host=args.bind,
        bind_port=args.port,
        observer=observer,
        policy=policy,
    )

    if not runtime.start():
        print("[sandboxed_runtime] failed to publish hidden service", file=sys.stderr)
        return 1

    print(
        f"[sandboxed_runtime] {runtime.name} \u2192 {runtime.address} "
        f"(local {runtime.local_url}, sandbox=on)"
    )
    try:
        runtime.join()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
