"""
Obscura47 — VPS Server Launcher

Runs both the bootstrap registry and the exit node on a single server.
This is the recommended way to deploy on your VPS.

Usage:
    python server.py
    python server.py --registry-port 8470 --exit-port 6000

The registry handles peer discovery and admin operations.
The exit node handles egress traffic for the network.
"""

import argparse
import os
import sys
import signal
import threading
import time


def main():
    parser = argparse.ArgumentParser(description="Obscura47 VPS Server (registry + exit node)")
    parser.add_argument("--registry-port", type=int, default=None,
                        help="Registry port (default: OBSCURA_REGISTRY_PORT or 8470)")
    parser.add_argument("--registry-host", type=str, default="0.0.0.0",
                        help="Registry bind address (default: 0.0.0.0)")
    parser.add_argument("--exit-port", type=int, default=None,
                        help="Exit node TCP port (default: OBSCURA_EXIT_LISTEN_PORT or 6000)")
    parser.add_argument("--no-exit", action="store_true",
                        help="Run registry only (no exit node)")
    args = parser.parse_args()

    # Apply port overrides to env before importing modules
    if args.registry_port is not None:
        os.environ["OBSCURA_REGISTRY_PORT"] = str(args.registry_port)
    if args.exit_port is not None:
        os.environ["OBSCURA_EXIT_LISTEN_PORT"] = str(args.exit_port)

    from src.utils.config import REGISTRY_PORT, EXIT_LISTEN_PORT, EXIT_WS_PORT

    registry_port = args.registry_port or REGISTRY_PORT
    exit_port = args.exit_port or EXIT_LISTEN_PORT

    print("=" * 60)
    print("  Obscura47 VPS Server")
    print("=" * 60)
    print(f"  Registry:   {args.registry_host}:{registry_port}")
    if not args.no_exit:
        print(f"  Exit node:  0.0.0.0:{exit_port} (TCP)")
        print(f"  Exit WS:    0.0.0.0:{EXIT_WS_PORT}")
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
    if not args.no_exit:
        def run_exit():
            nonlocal exit_node_instance
            try:
                from src.core.exit_node import ExitNode
                exit_node_instance = ExitNode(port=exit_port)
                exit_node_instance.start_server()
            except Exception as e:
                print(f"[server] Exit node error: {e}", flush=True)

        exit_thread = threading.Thread(target=run_exit, daemon=True)
        exit_thread.start()
        # Give exit node a moment to bind its ports
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
        print("[server] Stopped.")


if __name__ == "__main__":
    main()
