"""CLI entrypoint for the reference agent harness.

Examples:

    # Bring up an agent with the default /, /health, /info routes.
    python -m src.agent --name demo --key data/agent.pem

    # Use a user-defined AgentApp (factory or instance) for routes.
    python -m src.agent --name demo --key data/agent.pem \\
        --app my_pkg.my_module:build_app
"""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Any

from src.agent.app import AgentApp
from src.agent.runtime import AgentRuntime


def _load_app(spec: str) -> AgentApp:
    if ":" not in spec:
        raise SystemExit("--app must be MODULE:ATTR (e.g. my_pkg.my_module:app)")
    module_path, attr = spec.split(":", 1)
    module = importlib.import_module(module_path)
    obj: Any = getattr(module, attr)
    if callable(obj) and not isinstance(obj, AgentApp):
        obj = obj()
    if not isinstance(obj, AgentApp):
        raise SystemExit(
            f"--app {spec!r} did not resolve to an AgentApp "
            f"(got {type(obj).__name__})"
        )
    return obj


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.agent",
        description=(
            "Publish a local HTTP application as a `.obscura` hidden service."
        ),
    )
    parser.add_argument(
        "--name", default="agent",
        help="display name surfaced in the default /info route",
    )
    parser.add_argument(
        "--key", default=None,
        help=(
            "path to the service ECC keypair (PEM); created if missing. "
            "Defaults to ~/.obscura47/sites/<name>.pem when omitted."
        ),
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
        help=(
            "optional .obscura address of a collector to forward "
            "observability events to"
        ),
    )
    parser.add_argument(
        "--observatory-jsonl", default=None,
        help=(
            "optional local JSONL path that mirrors every observability "
            "event before it leaves the process"
        ),
    )

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args

    add_sandbox_arguments(parser)
    args = parser.parse_args(argv)

    from src.agent.observatory import build_observer_from_flags

    observer = build_observer_from_flags(
        actor=args.name,
        remote_addr=args.observatory,
        jsonl_path=args.observatory_jsonl,
    )

    policy = policy_from_args(args)

    from src.utils.sites import load_or_create_site_key

    _priv, _pub, key_path, _created = load_or_create_site_key(
        name=args.name, key=args.key,
    )

    app = _load_app(args.app) if args.app else None
    runtime = AgentRuntime(
        name=args.name,
        key_path=key_path,
        app=app,
        bind_host=args.bind,
        bind_port=args.port,
        observer=observer,
        policy=policy,
    )

    if not runtime.start():
        print("[agent] failed to publish hidden service", file=sys.stderr)
        return 1

    print(f"[agent] {runtime.name} → {runtime.address} (local {runtime.local_url})")
    try:
        runtime.join()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
