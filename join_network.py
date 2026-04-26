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
    python join_network.py host ./mysite --name myblog   # Named site (key at ~/.obscura47/sites/myblog.pem)
    python join_network.py host ./mysite --key /path.pem # Explicit key path
    python join_network.py host list          # List all hosted sites and their addresses
    python join_network.py host enable ./mysite --name myblog   # Install per-site background service
    python join_network.py host disable --name myblog           # Remove background service
    python join_network.py host publish ./mysite --name myblog  # Write manifest, optionally register, and host
    python join_network.py host write-manifest ./mysite --name myblog  # Create /.well-known/obscura.json
    python join_network.py host register-directory directory.obscura --name myblog   # Register site in a directory
    python join_network.py host unregister-directory directory.obscura --name myblog # Remove site from a directory
    python join_network.py directory          # Run an opt-in .obscura directory service
    python join_network.py directory list directory.obscura [query]    # Browse listings
    python join_network.py directory get directory.obscura site.obscura # Show one listing

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
    "directory": "Directory  — publish an opt-in .obscura site directory",
    "host": "Host       — publish a local site/service as a .obscura address",
    "open": "Open       — open a .obscura address in a browser",
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


def run_role(role: str, arg: str | None = None,
             site_name: str | None = None, key_path: str | None = None):
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
    elif role == "directory":
        from src.agent.directory import main as run_directory
        run_directory([])
    elif role == "host":
        _run_host(arg, site_name=site_name, key_path=key_path)


def _saved_target_for_site(site_name: str | None) -> str | None:
    if not site_name:
        return None
    from src.utils.sites import load_site_config

    config = load_site_config(site_name)
    return config.target if config else None


def _run_host(arg: str | None, site_name: str | None = None, key_path: str | None = None):
    """Publish a local directory or service as a `.obscura` hidden service."""
    from src.core.hidden_service import HiddenServiceHost
    from src.utils.sites import load_or_create_site_key, load_site_config, save_site_config

    if not arg:
        arg = _saved_target_for_site(site_name)

    if not arg:
        print("  [!] host mode needs a target: a directory path or host:port")
        print("      e.g.  python join_network.py host ./mysite")
        print("            python join_network.py host 127.0.0.1:8000")
        if site_name:
            print(f"            or save one first for site {site_name!r} and rerun with --name")
        sys.exit(1)

    target_host, target_port = _resolve_host_target(arg)
    if site_name and not key_path:
        config = load_site_config(site_name)
        if config and config.key_path:
            key_path = config.key_path
    _priv, _pub, resolved_key, _created = load_or_create_site_key(
        name=site_name, key=key_path,
    )
    if site_name:
        save_site_config(site_name, key_path=resolved_key, target=arg)
    host = HiddenServiceHost(target_host, target_port, resolved_key)

    label = site_name or os.path.basename(resolved_key).removesuffix(".pem")
    print()
    print(f"  site name:         {label}")
    print(f"  .obscura address:  {host.address}")
    print(f"  serving:           {target_host}:{target_port}")
    print(f"  key file:          {resolved_key}")
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


def _host_list():
    """Print all `.obscura` sites in the sites directory."""
    from src.utils.daemon import daemon_installed
    from src.utils.sites import list_sites, SITES_DIR

    sites = list(list_sites())
    if not sites:
        print(f"\n  No sites found in {SITES_DIR}")
        print("  Host a site first:  python join_network.py host ./mydir --name mysite\n")
        return

    print(f"\n  Sites in {SITES_DIR}:\n")
    for s in sites:
        print(f"    {s.name:<20s} {s.address}")
        print(f"    {'':20s} key: {s.key_path}")
        if s.target:
            print(f"    {'':20s} target: {s.target}")
        print(
            f"    {'':20s} background service: "
            f"{'installed' if daemon_installed(s.name) else 'not installed'}"
        )
        print()


def _host_export_key(argv: list[str]):
    from src.utils.sites import export_key
    name, _ = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for export-key")
        sys.exit(1)
    dest = "."
    for i, a in enumerate(argv):
        if not a.startswith("--") and a not in ("export-key",):
            dest = a
            break
    try:
        out = export_key(name, dest)
        print(f"  Exported key for site {name!r} to {out}")
    except FileNotFoundError as e:
        print(f"  [!] {e}")
        sys.exit(1)


def _host_import_key(argv: list[str]):
    from src.utils.sites import import_key
    from src.utils.onion_addr import address_from_pubkey
    from src.core.encryptions import ecc_load_or_create_keypair

    name, _ = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for import-key")
        sys.exit(1)
    src = None
    for a in argv:
        if not a.startswith("--") and a not in ("import-key",) and name != a:
            src = a
            break
    if not src:
        print("  [!] import-key needs a source .pem file path")
        sys.exit(1)
    try:
        dest = import_key(name, src)
        _, pub = ecc_load_or_create_keypair(dest)
        addr = address_from_pubkey(pub)
        print(f"  Imported key as site {name!r} → {addr}")
        print(f"  Key stored at {dest}")
    except (FileNotFoundError, FileExistsError) as e:
        print(f"  [!] {e}")
        sys.exit(1)


def _host_enable(argv: list[str]):
    from src.utils.daemon import install_daemon
    from src.utils.onion_addr import address_from_pubkey
    from src.utils.sites import load_or_create_site_key, load_site_config, save_site_config

    name, key = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for enable")
        sys.exit(1)

    positional = _strip_host_flags(argv)
    target = positional[0] if positional else None
    config = load_site_config(name)
    if not key and config and config.key_path:
        key = config.key_path
    if not target:
        target = config.target if config else None
    if not target:
        print("  [!] enable needs a target: directory path or host:port")
        print("      e.g.  python join_network.py host enable ./mysite --name mysite")
        print("      or remember one first with: python join_network.py host ./mysite --name mysite")
        sys.exit(1)

    try:
        _, pub, key_path, _created = load_or_create_site_key(
            name=name, key=key,
        )
        save_site_config(name, key_path=key_path, target=target)
        reference = install_daemon(name, target, key_path=key_path)
        print()
        print(f"  Installed background service for {name!r}")
        print(f"  .obscura address:  {address_from_pubkey(pub)}")
        print(f"  target:            {target}")
        print(f"  key file:          {key_path}")
        print(f"  service:           {reference}")
        print()
    except RuntimeError as e:
        print(f"  [!] {e}")
        sys.exit(1)


def _host_disable(argv: list[str]):
    from src.utils.daemon import uninstall_daemon

    name, _ = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for disable")
        sys.exit(1)

    try:
        removed = uninstall_daemon(name)
    except RuntimeError as e:
        print(f"  [!] {e}")
        sys.exit(1)

    if not removed:
        print(f"  [!] no background service found for site {name!r}")
        sys.exit(1)

    print(f"  Removed background service for site {name!r}")


def _host_rotate_key(argv: list[str]):
    from src.utils.sites import rotate_key
    from src.utils.onion_addr import address_from_pubkey

    name, _ = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for rotate-key")
        sys.exit(1)

    print()
    print(f"  WARNING: Rotating the key for site {name!r} will permanently")
    print("  change its .obscura address. Anyone using the old address will")
    print("  no longer be able to reach this site.")
    print()
    resp = input("  Continue? [y/N] ").strip().lower()
    if resp not in ("y", "yes"):
        print("  Aborted.")
        return

    _, pub, path, backup = rotate_key(name)
    addr = address_from_pubkey(pub)
    print(f"\n  New address: {addr}")
    print(f"  Key file:    {path}")
    if backup:
        print(f"  Old key:     {backup}")
    print()


def _parse_repeated_flag(argv: list[str], flag: str) -> list[str]:
    values: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == flag and i + 1 < len(argv):
            values.append(argv[i + 1])
            i += 2
        elif arg.startswith(flag + "="):
            values.append(arg.split("=", 1)[1])
            i += 1
        else:
            i += 1
    return values


def _single_flag_value(argv: list[str], flag: str) -> str | None:
    vals = _parse_repeated_flag(argv, flag)
    return vals[-1] if vals else None


def _strip_flags(argv: list[str], flags_with_values: tuple[str, ...]) -> list[str]:
    positional: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in flags_with_values and i + 1 < len(argv):
            i += 2
        elif any(arg.startswith(flag + "=") for flag in flags_with_values):
            i += 1
        else:
            positional.append(arg)
            i += 1
    return positional


def _host_write_manifest(argv: list[str]):
    from src.core.encryptions import ecc_load_or_create_keypair
    from src.utils.onion_addr import address_from_pubkey
    from src.utils.sites import load_or_create_site_key, load_site_config, write_site_manifest

    name, key = _parse_host_flags(argv)
    positional = _strip_flags(
        argv,
        ("--name", "--key", "--title", "--description", "--tag"),
    )
    positional = [a for a in positional if not a.startswith("--")]
    site_dir = positional[0] if positional else None
    if not site_dir:
        print("  [!] write-manifest needs a site directory")
        print("      e.g.  python join_network.py host write-manifest ./mysite --name mysite")
        sys.exit(1)

    if name and not key:
        config = load_site_config(name)
        if config and config.key_path:
            key = config.key_path

    _priv, pub, key_path, _created = load_or_create_site_key(name=name, key=key)
    address = address_from_pubkey(pub)
    title = _single_flag_value(argv, "--title") or (name or "")
    description = _single_flag_value(argv, "--description") or ""
    tags = _parse_repeated_flag(argv, "--tag")

    try:
        manifest_path = write_site_manifest(
            site_dir,
            address,
            title=title,
            description=description,
            tags=tags,
        )
    except FileNotFoundError as e:
        print(f"  [!] {e}")
        sys.exit(1)

    print()
    print(f"  Wrote manifest for {address}")
    print(f"  site directory:    {site_dir}")
    print(f"  manifest path:     {manifest_path}")
    print(f"  key file:          {key_path}")
    print()


def _schedule_directory_registration(
    site_name: str,
    directory_addr: str,
    *,
    initial_delay: float = 2.0,
    retry_delay: float = 3.0,
    attempts: int = 5,
):
    def _worker():
        if initial_delay > 0:
            time.sleep(initial_delay)
        for attempt in range(1, attempts + 1):
            try:
                _host_register_directory([directory_addr, "--name", site_name])
                return
            except SystemExit:
                if attempt >= attempts:
                    print()
                    print(
                        f"  [!] Could not register site {site_name!r} in {directory_addr} "
                        f"after {attempts} attempts."
                    )
                    print()
                    return
                time.sleep(retry_delay)

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"directory-register-{site_name}",
    ).start()


def _host_publish(argv: list[str]):
    name, key = _parse_host_flags(argv)
    if not name:
        print("  [!] --name is required for publish")
        sys.exit(1)

    directory_addr = _single_flag_value(argv, "--directory")
    positional = _strip_flags(
        argv,
        ("--name", "--key", "--directory", "--title", "--description", "--tag"),
    )
    positional = [a for a in positional if not a.startswith("--")]
    site_dir = positional[0] if positional else None
    if not site_dir:
        print("  [!] publish needs a site directory")
        print("      e.g.  python join_network.py host publish ./mysite --name mysite")
        sys.exit(1)

    manifest_args = [site_dir, "--name", name]
    if key:
        manifest_args.extend(["--key", key])
    title = _single_flag_value(argv, "--title")
    if title:
        manifest_args.extend(["--title", title])
    description = _single_flag_value(argv, "--description")
    if description:
        manifest_args.extend(["--description", description])
    for tag in _parse_repeated_flag(argv, "--tag"):
        manifest_args.extend(["--tag", tag])

    _host_write_manifest(manifest_args)

    if directory_addr:
        print(f"  Will register in directory: {directory_addr}")
        print()
        _schedule_directory_registration(name, directory_addr)

    _run_host(site_dir, site_name=name, key_path=key)


def _site_address_for_name(name: str) -> tuple[str, str]:
    from src.utils.onion_addr import address_from_pubkey
    from src.utils.sites import load_site_config, load_or_create_site_key

    config = load_site_config(name)
    key = config.key_path if config and config.key_path else None
    _priv, pub, key_path, _created = load_or_create_site_key(name=name, key=key)
    return address_from_pubkey(pub), key_path


def _host_register_directory(argv: list[str], *, unregister: bool = False):
    from src.agent.client import ToolCallError
    from src.agent.directory import DirectoryClient
    from src.utils.visitor import ensure_proxy_running

    name, _key = _parse_host_flags(argv)
    if not name:
        print(f"  [!] --name is required for {'unregister-directory' if unregister else 'register-directory'}")
        sys.exit(1)

    positional = _strip_host_flags(argv)
    directory_addr = positional[0] if positional else None
    if not directory_addr:
        print("  [!] directory address is required")
        print("      e.g.  python join_network.py host register-directory directory.obscura --name mysite")
        sys.exit(1)

    if not ensure_proxy_running():
        print("  [!] could not start the local proxy")
        sys.exit(1)

    site_addr, key_path = _site_address_for_name(name)
    client = DirectoryClient(directory_addr)
    try:
        result = (
            client.unregister(site_addr)
            if unregister
            else client.register(site_addr)
        )
    except ToolCallError as e:
        print(f"  [!] [{e.code}] {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"  [!] {e}")
        sys.exit(1)

    print()
    print(
        f"  {'Removed' if unregister else 'Registered'} {site_addr} "
        f"{'from' if unregister else 'in'} {directory_addr}"
    )
    print(f"  key file:          {key_path}")
    if not unregister:
        print(f"  title:             {result.get('title', '')}")
        if result.get("tags"):
            print(f"  tags:              {', '.join(result['tags'])}")
    print()


def _directory_client(directory_addr: str):
    from src.agent.directory import DirectoryClient
    from src.utils.visitor import ensure_proxy_running

    if not ensure_proxy_running():
        print("  [!] could not start the local proxy")
        sys.exit(1)
    return DirectoryClient(directory_addr)


def _directory_list(argv: list[str]):
    from src.agent.client import ToolCallError

    positional = [a for a in argv if not a.startswith("--")]
    directory_addr = positional[0] if positional else None
    query = positional[1] if len(positional) >= 2 else ""
    if not directory_addr:
        print("  [!] directory address is required")
        print("      e.g.  python join_network.py directory list directory.obscura")
        sys.exit(1)

    limit_raw = _single_flag_value(argv, "--limit")
    limit = int(limit_raw) if limit_raw else 20

    client = _directory_client(directory_addr)
    try:
        result = client.list(query=query, limit=limit)
    except ToolCallError as e:
        print(f"  [!] [{e.code}] {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"  [!] {e}")
        sys.exit(1)

    listings = result.get("listings", [])
    total = result.get("total", len(listings))
    print()
    print(f"  Directory: {directory_addr}")
    print(f"  Results:   {len(listings)} / {total}")
    print()
    if not listings:
        print("  No listings found.")
        print()
        return
    for row in listings:
        print(f"    {row.get('address', ''):<24s} {row.get('title', '')}")
        if row.get("description"):
            print(f"    {'':24s} {row['description']}")
        if row.get("tags"):
            print(f"    {'':24s} tags: {', '.join(row['tags'])}")
        print()


def _directory_get(argv: list[str]):
    from src.agent.client import ToolCallError

    positional = [a for a in argv if not a.startswith("--")]
    directory_addr = positional[0] if positional else None
    site_addr = positional[1] if len(positional) >= 2 else None
    if not directory_addr or not site_addr:
        print("  [!] directory address and site address are required")
        print("      e.g.  python join_network.py directory get directory.obscura alpha.obscura")
        sys.exit(1)

    client = _directory_client(directory_addr)
    try:
        row = client.get(site_addr)
    except ToolCallError as e:
        print(f"  [!] [{e.code}] {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"  [!] {e}")
        sys.exit(1)

    print()
    print(f"  address:           {row.get('address', '')}")
    print(f"  title:             {row.get('title', '')}")
    print(f"  description:       {row.get('description', '')}")
    if row.get("tags"):
        print(f"  tags:              {', '.join(row['tags'])}")
    print()


def start_roles(roles: list[str], host_arg: str | None = None,
                site_name: str | None = None, key_path: str | None = None):
    """Start one or more roles. First role runs in main thread, rest in daemon threads."""
    if not roles:
        return

    print(f"\n  Starting: {', '.join(roles)}")
    print("  Press Ctrl+C to stop.\n")

    # Start all but the last in background threads
    for role in roles[:-1]:
        t = threading.Thread(
            target=run_role,
            args=(role, host_arg if role == "host" else None, site_name, key_path),
            daemon=True,
        )
        t.start()
        print(f"  [+] {role} started")
        time.sleep(0.5)  # Stagger startups slightly

    # Last role runs in main thread (so Ctrl+C works)
    last = roles[-1]
    print(f"  [+] {last} starting (main thread)...\n")
    run_role(last, host_arg if last == "host" else None, site_name, key_path)


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
    print("    7) Directory       — Run an opt-in site directory")
    print()

    choice = input("  Enter choice [1-7]: ").strip()

    role_map = {
        "1": ["node"],
        "2": ["exit"],
        "3": ["node", "exit"],
        "4": ["registry", "node", "exit", "proxy"],
        "5": ["proxy"],
        "7": ["directory"],
    }

    if choice == "6":
        target = input("  Directory to serve, or host:port of existing service: ").strip()
        return ["host"], target

    roles = role_map.get(choice)
    if not roles:
        print("  Invalid choice.")
        sys.exit(1)

    return roles, None


def _parse_host_flags(argv: list[str]) -> tuple[str | None, str | None]:
    """Extract --name and --key from trailing argv, returning (name, key)."""
    name = key = None
    i = 0
    while i < len(argv):
        if argv[i] == "--name" and i + 1 < len(argv):
            name = argv[i + 1]
            i += 2
        elif argv[i].startswith("--name="):
            name = argv[i].split("=", 1)[1]
            i += 1
        elif argv[i] == "--key" and i + 1 < len(argv):
            key = argv[i + 1]
            i += 2
        elif argv[i].startswith("--key="):
            key = argv[i].split("=", 1)[1]
            i += 1
        else:
            i += 1
    return name, key


def _strip_host_flags(argv: list[str]) -> list[str]:
    """Return positional args after removing --name/--key flags and their values."""
    return _strip_flags(argv, ("--name", "--key"))


def main():
    signal.signal(signal.SIGINT, lambda s, f: (print("\n\n  Shutting down..."), sys.exit(0)))

    check_dependencies()

    host_arg: str | None = None
    site_name: str | None = None
    key_path: str | None = None

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()

        if "+" in arg:
            roles = [r.strip() for r in arg.split("+") if r.strip() in ROLES]
        elif arg == "all":
            roles = ["registry", "node", "exit", "proxy"]
        elif arg == "open":
            from src.utils.visitor import open_in_browser
            url = sys.argv[2] if len(sys.argv) >= 3 else ""
            if open_in_browser(url=url):
                print("  Browser launched with .obscura proxy routing.")
            else:
                print("  [!] Could not start the proxy or open the browser.")
            return
        elif arg == "directory":
            sub = sys.argv[2].lower() if len(sys.argv) >= 3 else ""
            if sub == "list":
                _directory_list(sys.argv[3:])
                return
            if sub == "get":
                _directory_get(sys.argv[3:])
                return
            roles = ["directory"]
        elif arg == "host":
            sub = sys.argv[2].lower() if len(sys.argv) >= 3 else ""
            if sub == "list":
                _host_list()
                return
            if sub == "enable":
                _host_enable(sys.argv[3:])
                return
            if sub == "disable":
                _host_disable(sys.argv[3:])
                return
            if sub == "publish":
                _host_publish(sys.argv[3:])
                return
            if sub == "export-key":
                _host_export_key(sys.argv[3:])
                return
            if sub == "import-key":
                _host_import_key(sys.argv[3:])
                return
            if sub == "rotate-key":
                _host_rotate_key(sys.argv[3:])
                return
            if sub == "write-manifest":
                _host_write_manifest(sys.argv[3:])
                return
            if sub == "register-directory":
                _host_register_directory(sys.argv[3:])
                return
            if sub == "unregister-directory":
                _host_register_directory(sys.argv[3:], unregister=True)
                return
            if not sub:
                print("  [!] host mode needs a target argument")
                print("      e.g.  python join_network.py host ./mysite")
                print("            python join_network.py host list")
                print("            python join_network.py host enable ./mysite --name mysite")
                print("            python join_network.py host disable --name mysite")
                print("            python join_network.py host publish ./mysite --name mysite")
                print("            python join_network.py host write-manifest ./mysite --name mysite")
                print("            python join_network.py host register-directory directory.obscura --name mysite")
                print("            python join_network.py host unregister-directory directory.obscura --name mysite")
                print("            python join_network.py host export-key --name mysite")
                print("            python join_network.py host import-key key.pem --name mysite")
                print("            python join_network.py host rotate-key --name mysite")
                sys.exit(1)
            roles = ["host"]
            if sub.startswith("--"):
                host_arg = None
                site_name, key_path = _parse_host_flags(sys.argv[2:])
                if not site_name:
                    print("  [!] host mode with saved config needs --name")
                    sys.exit(1)
            else:
                host_arg = sys.argv[2]
                site_name, key_path = _parse_host_flags(sys.argv[3:])
        elif arg in ROLES:
            roles = [arg]
        else:
            print(f"  Unknown role: {arg}")
            print(f"  Valid roles: {', '.join(ROLES.keys())}, all, or combine with + (e.g. node+exit)")
            sys.exit(1)
    else:
        roles, host_arg = interactive_menu()

    start_roles(roles, host_arg, site_name=site_name, key_path=key_path)


if __name__ == "__main__":
    main()
