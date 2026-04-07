#!/usr/bin/env python3
"""
This file is for network administrators only. Do not distribute with public releases.

Obscura47 — Admin CLI
Manage the Obscura network: approve/reject nodes, activate kill switch, view status.

Usage:
    python admin_cli.py keygen                    # Generate admin ECDSA keypair
    python admin_cli.py status                    # Show network health
    python admin_cli.py pending                   # List pending exit nodes
    python admin_cli.py approve <peer_id>         # Approve an exit node
    python admin_cli.py reject <peer_id>          # Reject an exit node
    python admin_cli.py kill "reason"             # Activate kill switch
    python admin_cli.py revive                    # Deactivate kill switch
    python admin_cli.py peers                     # List all peers
    python admin_cli.py remove <peer_id>          # Remove a peer

Environment variables:
    OBSCURA_REGISTRY_URL         Registry server URL (default: http://localhost:8470)
    OBSCURA_REGISTRY_ADMIN_KEY   Admin bearer token for registry access
"""

import os
import sys
import argparse
import json
import base64
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional


def _load_dotenv():
    """Load .env file from the project root into os.environ (no dependencies)."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


_load_dotenv()

# Configuration from environment
REGISTRY_URL = os.getenv("OBSCURA_REGISTRY_URL", "http://localhost:8470").rstrip("/")
REGISTRY_ADMIN_KEY = os.getenv("OBSCURA_REGISTRY_ADMIN_KEY", "")
ADMIN_KEY_DIR = os.path.expanduser("~/.obscura47")


def _ensure_admin_dir():
    """Ensure admin key directory exists."""
    Path(ADMIN_KEY_DIR).mkdir(parents=True, exist_ok=True)


def _supports_colors() -> bool:
    """Check if terminal supports ANSI colors."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _color(text: str, color_code: str) -> str:
    """Wrap text in ANSI color code if terminal supports it."""
    if not _supports_colors():
        return text
    reset = "\033[0m"
    return f"{color_code}{text}{reset}"


def _http_request(method: str, endpoint: str, data: Optional[dict] = None) -> dict:
    """Make HTTP request to registry with auth header."""
    url = f"{REGISTRY_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if REGISTRY_ADMIN_KEY:
        headers["Authorization"] = f"Bearer {REGISTRY_ADMIN_KEY}"

    body = None
    if data:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            response_data = response.read().decode("utf-8")
            if response_data:
                return json.loads(response_data)
            return {}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            error_json = json.loads(error_body)
            raise RuntimeError(f"HTTP {e.code}: {error_json.get('detail', error_body)}")
        except json.JSONDecodeError:
            raise RuntimeError(f"HTTP {e.code}: {error_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}")


def cmd_keygen(args):
    """Generate admin ECDSA keypair."""
    try:
        from Crypto.PublicKey import ECC
    except ImportError:
        print("Error: pycryptodome is required. Install with: pip install pycryptodome")
        sys.exit(1)

    _ensure_admin_dir()

    # Generate P-256 keypair
    key = ECC.generate(curve="P-256")
    private_pem = key.export_key(format="PEM")
    public_pem = key.public_key().export_key(format="PEM")

    # Save to files
    priv_path = os.path.join(ADMIN_KEY_DIR, "admin_key.pem")
    pub_path = os.path.join(ADMIN_KEY_DIR, "admin_pub.pem")

    with open(priv_path, "w") as f:
        f.write(private_pem)
    os.chmod(priv_path, 0o600)

    with open(pub_path, "w") as f:
        f.write(public_pem)

    # Print instructions
    print(_color("✓ Generated ECDSA P-256 keypair", "\033[92m"))
    print(f"  Private key: {priv_path} (mode 0600)")
    print(f"  Public key:  {pub_path}")
    print()
    print(_color("Set this in your .env as OBSCURA_ADMIN_PUB_PEM:", "\033[94m"))
    print()
    print(public_pem)
    print()
    print("Then restart the registry server for the changes to take effect.")


def cmd_status(args):
    """Show network health."""
    try:
        result = _http_request("GET", "/admin/health")
        print(_color("Network Health", "\033[94m"))
        print(f"  Total peers: {result.get('total_peers', 0)}")
        print()
        peers = result.get("peers", [])
        if not peers:
            print("  (no peers)")
            return

        # Group by status
        approved = [p for p in peers if p.get("approved")]
        pending = [p for p in peers if not p.get("approved")]

        if approved:
            print(_color(f"Approved ({len(approved)}):", "\033[92m"))
            for p in approved:
                heartbeat = p.get("time_since_heartbeat", -1)
                status_str = "online" if heartbeat < 120 else "stale"
                status_color = "\033[92m" if heartbeat < 120 else "\033[93m"
                print(
                    f"  {p['peer_id'][:12]}... | {p['host']}:{p['port']} "
                    f"| {_color(status_str, status_color)} ({heartbeat:.0f}s)"
                )

        if pending:
            print(_color(f"Pending ({len(pending)}):", "\033[93m"))
            for p in pending:
                print(f"  {p['peer_id'][:12]}... | {p['host']}:{p['port']}")

    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_pending(args):
    """List pending exit nodes."""
    try:
        result = _http_request("GET", "/admin/pending")
        pending = result.get("pending", [])

        if not pending:
            print("No pending exit nodes.")
            return

        print(_color(f"Pending Exit Nodes ({len(pending)}):", "\033[93m"))
        for p in pending:
            print(f"  {p['peer_id']}")
            print(f"    Host: {p['host']}:{p['port']}")
            if p.get("ws_port"):
                proto = "wss" if p.get("ws_tls") else "ws"
                print(f"    WebSocket: {proto}://{p['host']}:{p['ws_port']}")

    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_approve(args):
    """Approve an exit node."""
    if not args.peer_id:
        print("Error: peer_id required")
        sys.exit(1)

    try:
        result = _http_request("POST", f"/admin/approve/{args.peer_id}")
        print(_color(f"✓ Approved {args.peer_id[:12]}...", "\033[92m"))
    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_reject(args):
    """Reject an exit node."""
    if not args.peer_id:
        print("Error: peer_id required")
        sys.exit(1)

    try:
        result = _http_request("POST", f"/admin/reject/{args.peer_id}")
        print(_color(f"✓ Rejected {args.peer_id[:12]}...", "\033[92m"))
    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_kill(args):
    """Activate kill switch."""
    if not args.reason:
        print("Error: reason required (e.g., 'Network compromise detected')")
        sys.exit(1)

    # Load admin private key
    priv_path = os.path.join(ADMIN_KEY_DIR, "admin_key.pem")
    if not os.path.exists(priv_path):
        print(_color("Error: admin key not found. Run 'keygen' first.", "\033[91m"))
        sys.exit(1)

    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
    except ImportError:
        print("Error: pycryptodome is required. Install with: pip install pycryptodome")
        sys.exit(1)

    with open(priv_path, "r") as f:
        key = ECC.import_key(f.read())

    timestamp = time.time()
    message = f"KILL:{args.reason}:{timestamp}".encode("utf-8")
    h = SHA256.new(message)
    signer = DSS.new(key, "fips-186-3")
    signature = base64.b64encode(signer.sign(h)).decode("utf-8")

    try:
        payload = {
            "reason": args.reason,
            "signature": signature,
            "timestamp": timestamp,
        }
        result = _http_request("POST", "/admin/kill", payload)
        print(_color("✓ Kill switch ACTIVATED", "\033[91m"))
        print(f"  Reason: {args.reason}")
        print(f"  Timestamp: {timestamp}")
    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_revive(args):
    """Deactivate kill switch."""
    # Load admin private key
    priv_path = os.path.join(ADMIN_KEY_DIR, "admin_key.pem")
    if not os.path.exists(priv_path):
        print(_color("Error: admin key not found. Run 'keygen' first.", "\033[91m"))
        sys.exit(1)

    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
    except ImportError:
        print("Error: pycryptodome is required. Install with: pip install pycryptodome")
        sys.exit(1)

    with open(priv_path, "r") as f:
        key = ECC.import_key(f.read())

    timestamp = time.time()
    message = f"REVIVE:{timestamp}".encode("utf-8")
    h = SHA256.new(message)
    signer = DSS.new(key, "fips-186-3")
    signature = base64.b64encode(signer.sign(h)).decode("utf-8")

    try:
        payload = {
            "signature": signature,
            "timestamp": timestamp,
        }
        result = _http_request("POST", "/admin/revive", payload)
        print(_color("✓ Kill switch DEACTIVATED", "\033[92m"))
    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_peers(args):
    """List all peers."""
    try:
        result = _http_request("GET", "/admin/peers")
        peers = result.get("peers", [])

        if not peers:
            print("No peers registered.")
            return

        print(_color(f"All Peers ({len(peers)}):", "\033[94m"))
        for p in peers:
            role = p.get("role", "unknown")
            approved = p.get("approved", False)
            status = _color("approved", "\033[92m") if approved else _color("pending", "\033[93m")
            print(f"  {p['peer_id'][:12]}... | {p['host']}:{p['port']} | {role:4s} | {status}")

    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def cmd_remove(args):
    """Remove a peer."""
    if not args.peer_id:
        print("Error: peer_id required")
        sys.exit(1)

    try:
        result = _http_request("POST", f"/admin/remove/{args.peer_id}")
        print(_color(f"✓ Removed {args.peer_id[:12]}...", "\033[92m"))
    except Exception as e:
        print(_color(f"Error: {e}", "\033[91m"))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Obscura47 Network Admin CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python admin_cli.py keygen
  python admin_cli.py status
  python admin_cli.py pending
  python admin_cli.py approve <peer_id>
  python admin_cli.py kill "Critical vulnerability detected"
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # keygen
    subparsers.add_parser("keygen", help="Generate admin ECDSA keypair")

    # status
    subparsers.add_parser("status", help="Show network health")

    # pending
    subparsers.add_parser("pending", help="List pending exit nodes")

    # approve
    approve_parser = subparsers.add_parser("approve", help="Approve an exit node")
    approve_parser.add_argument("peer_id", help="Peer ID to approve")

    # reject
    reject_parser = subparsers.add_parser("reject", help="Reject an exit node")
    reject_parser.add_argument("peer_id", help="Peer ID to reject")

    # kill
    kill_parser = subparsers.add_parser("kill", help="Activate kill switch")
    kill_parser.add_argument("reason", help="Reason for kill switch activation")

    # revive
    subparsers.add_parser("revive", help="Deactivate kill switch")

    # peers
    subparsers.add_parser("peers", help="List all peers")

    # remove
    remove_parser = subparsers.add_parser("remove", help="Remove a peer")
    remove_parser.add_argument("peer_id", help="Peer ID to remove")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Dispatch to command handler
    cmd_func = globals().get(f"cmd_{args.command}")
    if cmd_func:
        cmd_func(args)
    else:
        print(f"Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
