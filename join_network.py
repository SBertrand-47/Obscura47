#!/usr/bin/env python3
"""
Obscura47 — Quick Join
Run this script to instantly join the Obscura network.

Usage:
    python join_network.py                    # Interactive mode (choose role)
    python join_network.py node               # Join as relay node
    python join_network.py exit               # Join as exit node
    python join_network.py node+exit          # Run both relay and exit
    python join_network.py all                # Run all components
    python join_network.py host ./mysite      # Host a directory as a .obscura site
    python join_network.py host 127.0.0.1:8000  # Host an existing local service

No build step required — runs directly from source.
"""

import sys
import os
import threading
import time
import signal

# Ensure we can import from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# UTF-8 console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


BANNER = r"""
   ____  __                          __ __ ______
  / __ \/ /_  ___________  _________/ // //__  /
 / / / / __ \/ ___/ ___/ / / / ___/ // /_  / /
/ /_/ / /_/ (__  ) /__/ /_/ / /  /__  __/ / /
\____/_.___/____/\___/\__,_/_/     /_/   /_/

         Anonymous Overlay Network
"""

ROLES = {
    "node": "Relay Node — forward encrypted traffic for others",
    "exit": "Exit Node  — provide internet egress for the network",
    "proxy": "Proxy      — local SOCKS proxy (browse through Obscura)",
    "registry": "Registry   — bootstrap server for peer discovery",
    "host": "Host       — publish a local site/service as a .obscura address",
}


def check_dependencies():
    """Verify required packages are installed."""
    missing = []
    try:
        import Crypto  # noqa: F401
    except ImportError:
        missing.append("pycryptodome")
    try:
        import websockets  # noqa: F401
    except ImportError:
        missing.append("websockets")
    try:
        import fastapi  # noqa: F401
    except ImportError:
        missing.append("fastapi")
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        missing.append("uvicorn")

    if missing:
        print(f"\n[!] Missing dependencies: {', '.join(missing)}")
        print("    Install them with:\n")
        print(f"    pip install -r requirements.txt\n")
        resp = input("    Install now? [Y/n] ").strip().lower()
        if resp in ("", "y", "yes"):
            import subprocess
            req_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])
            print()
        else:
            print("\n    Please install dependencies first.")
            sys.exit(1)


def run_role(role: str, arg: str | None = None):
    """Start a single role in the current thread (blocking)."""
    if role == "proxy":
        from src.core.proxy import start_proxy
        start_proxy()
    elif role == "node":
        from src.core.node import ObscuraNode
        from src.utils.config import NODE_LISTEN_PORT
        node = ObscuraNode(port=NODE_LISTEN_PORT)
        node.run()
        while True:
            time.sleep(1)
    elif role == "exit":
        from src.core.exit_node import ExitNode
        from src.utils.config import EXIT_LISTEN_PORT
        exit_node = ExitNode(port=EXIT_LISTEN_PORT)
        exit_node.start_server()
    elif role == "registry":
        from src.core.registry import run_registry
        run_registry()
    elif role == "host":
        _run_host(arg)


def _run_host(arg: str | None):
    """Publish a local directory or service as a `.obscura` hidden service."""
    from src.core.hidden_service import HiddenServiceHost

    if not arg:
        print("  [!] host mode needs a target: a directory path or host:port")
        print("      e.g.  python join_network.py host ./mysite")
        print("            python join_network.py host 127.0.0.1:8000")
        sys.exit(1)

    target_host, target_port = _resolve_host_target(arg)
    key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hs_service.pem")
    host = HiddenServiceHost(target_host, target_port, key_path)

    print()
    print(f"  .obscura address:  {host.address}")
    print(f"  serving:           {target_host}:{target_port}")
    print(f"  key file:          {key_path}")
    print()
    print("  Share the address above; anyone running a proxy with a route to")
    print("  the network can reach it with:  curl -x http://127.0.0.1:47477 "
          f"http://{host.address}/")
    print()

    host.run()


def _resolve_host_target(arg: str) -> tuple[str, int]:
    """If *arg* is host:port, return it; if it's a directory, start a local
    http.server on a random port and return that target."""
    if ":" in arg and not os.path.exists(arg):
        host_str, port_str = arg.rsplit(":", 1)
        return host_str, int(port_str)

    if not os.path.isdir(arg):
        print(f"  [!] '{arg}' is neither host:port nor an existing directory")
        sys.exit(1)

    import http.server
    import socketserver

    directory = os.path.abspath(arg)

    class _Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)
        def log_message(self, fmt, *args):
            return  # quiet

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"  [+] Local http.server serving {directory} on 127.0.0.1:{port}")
    return "127.0.0.1", port


def start_roles(roles: list[str], host_arg: str | None = None):
    """Start one or more roles. First role runs in main thread, rest in daemon threads."""
    if not roles:
        return

    print(f"\n  Starting: {', '.join(roles)}")
    print("  Press Ctrl+C to stop.\n")

    # Start all but the last in background threads
    for role in roles[:-1]:
        t = threading.Thread(target=run_role, args=(role, host_arg if role == "host" else None), daemon=True)
        t.start()
        print(f"  [+] {role} started")
        time.sleep(0.5)  # Stagger startups slightly

    # Last role runs in main thread (so Ctrl+C works)
    last = roles[-1]
    print(f"  [+] {last} starting (main thread)...\n")
    run_role(last, host_arg if last == "host" else None)


def interactive_menu():
    """Show an interactive menu for role selection."""
    print(BANNER)
    print("  Choose how to join the Obscura network:\n")
    print("    1) Relay Node      — Help others by forwarding traffic")
    print("    2) Exit Node       — Provide internet access to the network")
    print("    3) Relay + Exit    — Run both (recommended for contributors)")
    print("    4) Full Stack      — Run all components (node + exit + proxy + registry)")
    print("    5) Proxy Only      — Browse the internet through Obscura")
    print("    6) Host .obscura   — Publish a local site/service")
    print()

    choice = input("  Enter choice [1-6]: ").strip()

    role_map = {
        "1": ["node"],
        "2": ["exit"],
        "3": ["node", "exit"],
        "4": ["registry", "node", "exit", "proxy"],
        "5": ["proxy"],
    }

    if choice == "6":
        target = input("  Directory to serve, or host:port of existing service: ").strip()
        return ["host"], target

    roles = role_map.get(choice)
    if not roles:
        print("  Invalid choice.")
        sys.exit(1)

    return roles, None


def main():
    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: (print("\n\n  Shutting down..."), sys.exit(0)))

    check_dependencies()

    host_arg: str | None = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()

        # Handle combined roles like "node+exit"
        if "+" in arg:
            roles = [r.strip() for r in arg.split("+") if r.strip() in ROLES]
        elif arg == "all":
            roles = ["registry", "node", "exit", "proxy"]
        elif arg == "host":
            roles = ["host"]
            if len(sys.argv) < 3:
                print("  [!] host mode needs a target argument")
                print("      e.g.  python join_network.py host ./mysite")
                sys.exit(1)
            host_arg = sys.argv[2]
        elif arg in ROLES:
            roles = [arg]
        else:
            print(f"  Unknown role: {arg}")
            print(f"  Valid roles: {', '.join(ROLES.keys())}, all, or combine with + (e.g. node+exit)")
            sys.exit(1)
    else:
        roles, host_arg = interactive_menu()

    start_roles(roles, host_arg)


if __name__ == "__main__":
    main()
