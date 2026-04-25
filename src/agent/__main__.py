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
    args = parser.parse_args(argv)

    app = _load_app(args.app) if args.app else None
    runtime = AgentRuntime(
        name=args.name,
        key_path=args.key,
        app=app,
        bind_host=args.bind,
        bind_port=args.port,
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
