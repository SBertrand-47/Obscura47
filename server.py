"""
Obscura47 - VPS Server Launcher

Runs the bootstrap registry, an exit node, and a relay node on a single
server. This is the recommended way to deploy on your VPS - the relay
node gives the public network a reachable HS intro point so users
behind NAT can host services that anyone on the internet can dial.

Usage:
    python server.py
    python server.py --registry-port 8470 --exit-port 6000 --node-port 5001

Each role uses a distinct ECC keypair (OBSCURA_EXIT_KEY_PATH vs
OBSCURA_NODE_KEY_PATH) so a compromise of one role does not pivot to
the other.
"""

import argparse
import os
import sys
import signal
import threading
import time


def main():
    parser = argparse.ArgumentParser(description="Obscura47 VPS Server (registry + exit + node)")
    parser.add_argument("--registry-port", type=int, default=None,
                        help="Registry port (default: OBSCURA_REGISTRY_PORT or 8470)")
    parser.add_argument("--registry-host", type=str, default="0.0.0.0",
                        help="Registry bind address (default: 0.0.0.0)")
    parser.add_argument("--exit-port", type=int, default=None,
                        help="Exit node TCP port (default: OBSCURA_EXIT_LISTEN_PORT or 6000)")
    parser.add_argument("--node-port", type=int, default=None,
                        help="Relay node TCP port (default: OBSCURA_NODE_LISTEN_PORT or 5001)")
    parser.add_argument("--no-exit", action="store_true",
                        help="Skip the exit node role")
    parser.add_argument("--no-node", action="store_true",
                        help="Skip the relay node role")
    args = parser.parse_args()

    # Role gating. Default is all three roles (single-box deploys), but the
    # relay-node and exit roles can be turned off from the .env alone - no CLI
    # flags needed - so a registry+exit box that has a *dedicated* relay node
    # elsewhere stops advertising its own IP as a relay hop. That matters:
    # if the exit's IP is also handed out as a middle node, circuit builders
    # can consume it as a relay instead of as the exit, starving exit
    # selection and breaking clearnet/.obscura egress.
    def _env_truthy(name: str, default: bool) -> bool:
        v = os.getenv(name)
        if v is None or v.strip() == "":
            return default
        return v.strip().lower() in ("1", "true", "yes", "on")

    run_exit = not args.no_exit and _env_truthy("OBSCURA_RUN_EXIT", True)
    run_node = not args.no_node and _env_truthy("OBSCURA_RUN_NODE", True)

    # Apply port overrides to env before importing modules
    if args.registry_port is not None:
        os.environ["OBSCURA_REGISTRY_PORT"] = str(args.registry_port)
    if args.exit_port is not None:
        os.environ["OBSCURA_EXIT_LISTEN_PORT"] = str(args.exit_port)
    if args.node_port is not None:
        os.environ["OBSCURA_NODE_LISTEN_PORT"] = str(args.node_port)

    from src.utils.config import (
        REGISTRY_PORT, EXIT_LISTEN_PORT, EXIT_WS_PORT,
        NODE_LISTEN_PORT, NODE_WS_PORT,
    )

    registry_port = args.registry_port or REGISTRY_PORT
    exit_port = args.exit_port or EXIT_LISTEN_PORT
    node_port = args.node_port or NODE_LISTEN_PORT

    print("=" * 60)
    print("  Obscura47 VPS Server")
    print("=" * 60)
    print(f"  Registry:   {args.registry_host}:{registry_port}")
    if run_exit:
        print(f"  Exit node:  0.0.0.0:{exit_port} (TCP)")
        print(f"  Exit WS:    0.0.0.0:{EXIT_WS_PORT}")
    else:
        print("  Exit node:  disabled (OBSCURA_RUN_EXIT=false)")
    if run_node:
        print(f"  Relay node: 0.0.0.0:{node_port} (TCP)")
        print(f"  Node WS:    0.0.0.0:{NODE_WS_PORT}")
    else:
        print("  Relay node: disabled (OBSCURA_RUN_NODE=false; use a dedicated node host)")
    print()
    print("  Admin CLI:  python admin_cli.py status")
    print("=" * 60)
    print()

    # Handle Ctrl+C cleanly
    shutdown_event = threading.Event()

    def _signal_handler(sig, frame):
        print("\n[server] Shutting down...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Start exit node in background thread (before registry, since registry
    # blocks on uvicorn.run)
    exit_node_instance = None
    if run_exit:
        def _run_exit():
            nonlocal exit_node_instance
            try:
                from src.core.exit_node import ExitNode
                exit_node_instance = ExitNode(port=exit_port)
                exit_node_instance.start_server()
            except Exception as e:
                print(f"[server] Exit node error: {e}", flush=True)

        exit_thread = threading.Thread(target=_run_exit, daemon=True)
        exit_thread.start()
        # Give exit node a moment to bind its ports
        time.sleep(1)

    # Start relay node in another background thread. Uses a distinct
    # ECC keypair (OBSCURA_NODE_KEY_PATH) so the node identity is not
    # tied to the exit identity.
    node_instance = None
    if run_node:
        def _run_node():
            nonlocal node_instance
            try:
                from src.core.node import ObscuraNode
                node_instance = ObscuraNode(port=node_port)
                node_instance.start_server()
            except Exception as e:
                print(f"[server] Relay node error: {e}", flush=True)

        node_thread = threading.Thread(target=_run_node, daemon=True)
        node_thread.start()
        time.sleep(1)

    # Run registry (blocks until shutdown)
    try:
        import uvicorn
        from registry_server import app, TLS_CERT, TLS_KEY

        uvicorn_kwargs = {
            "host": args.registry_host,
            "port": registry_port,
            "log_level": "warning",
        }
        use_tls = bool(TLS_CERT and TLS_KEY)
        if use_tls:
            uvicorn_kwargs["ssl_certfile"] = TLS_CERT
            uvicorn_kwargs["ssl_keyfile"] = TLS_KEY

        scheme = "https" if use_tls else "http"
        print(f"[server] Registry listening on {scheme}://{args.registry_host}:{registry_port}")
        uvicorn.run(app, **uvicorn_kwargs)
    except KeyboardInterrupt:
        pass
    finally:
        print("[server] Cleaning up...")
        if exit_node_instance:
            try:
                exit_node_instance.shutdown()
            except Exception:
                pass
        if node_instance:
            try:
                node_instance.shutdown()
            except Exception:
                pass
        print("[server] Stopped.")


if __name__ == "__main__":
    main()
