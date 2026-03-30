"""
Obscura47 — Standalone Bootstrap Registry Server

Drop this single file on any public server (VPS, cloud instance, etc.) and run:

    python registry_server.py

That's it. Nodes will register and discover each other through this server.

Options:
    --port PORT    Port to listen on (default: 8470)
    --host HOST    Bind address (default: 0.0.0.0)

No dependencies beyond Python 3.10+.
"""

import argparse
import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Configuration ─────────────────────────────────────────────────
DEFAULT_PORT = 8470
PEER_TTL = 120  # seconds before a peer is considered dead

# ── In-memory peer store ──────────────────────────────────────────
_peers: dict[str, dict] = {}
_lock = threading.Lock()


def _expire():
    cutoff = time.time() - PEER_TTL
    with _lock:
        expired = [k for k, v in _peers.items() if v.get("ts", 0) < cutoff]
        for k in expired:
            del _peers[k]
    if expired:
        print(f"[registry] Expired {len(expired)} stale peer(s)")


def _expire_loop():
    while True:
        time.sleep(15)
        _expire()


def _stats():
    with _lock:
        roles = {}
        for p in _peers.values():
            r = p.get("role", "unknown")
            roles[r] = roles.get(r, 0) + 1
        return dict(roles), len(_peers)


def _stats_loop():
    while True:
        time.sleep(60)
        roles, total = _stats()
        print(f"[registry] Peers: {total} | {roles}")


# ── HTTP Handler ──────────────────────────────────────────────────

class RegistryHandler(BaseHTTPRequestHandler):
    """
    POST /register  — node announces itself { role, port, pub? }
    GET  /peers     — returns list of all live peers
    GET  /health    — simple health check
    """

    def log_message(self, fmt, *args):
        pass  # suppress default access logs

    def do_GET(self):
        if self.path == "/peers":
            _expire()
            with _lock:
                body = json.dumps(list(_peers.values())).encode()
            self._respond(200, body)

        elif self.path == "/health":
            roles, total = _stats()
            body = json.dumps({"status": "ok", "peers": total, "breakdown": roles}).encode()
            self._respond(200, body)

        else:
            self._respond(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path == "/register":
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                data = json.loads(raw)

                role = data.get("role")       # "node" | "exit" | "proxy"
                port = int(data.get("port"))
                pub  = data.get("pub")        # optional PEM public key

                # Use the real IP the request came from
                # Support X-Forwarded-For if behind a reverse proxy
                forwarded = self.headers.get("X-Forwarded-For")
                if forwarded:
                    host = forwarded.split(",")[0].strip()
                else:
                    host = self.client_address[0]

                key = f"{host}:{port}"
                peer = {
                    "host": host,
                    "port": port,
                    "role": role,
                    "ts": time.time(),
                }
                if pub:
                    peer["pub"] = pub

                with _lock:
                    is_new = key not in _peers
                    _peers[key] = peer

                if is_new:
                    print(f"[registry] + New {role} at {key}")
                self._respond(200, json.dumps({"ok": True, "your_ip": host}).encode())

            except Exception as e:
                self._respond(400, json.dumps({"error": str(e)}).encode())
        else:
            self._respond(404, b'{"error":"not found"}')

    def _respond(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


# ── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Obscura47 Bootstrap Registry")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = parser.parse_args()

    threading.Thread(target=_expire_loop, daemon=True).start()
    threading.Thread(target=_stats_loop, daemon=True).start()

    server = HTTPServer((args.host, args.port), RegistryHandler)
    print(f"=========================================")
    print(f"  Obscura47 Bootstrap Registry")
    print(f"  Listening on {args.host}:{args.port}")
    print(f"  Peer TTL: {PEER_TTL}s")
    print(f"=========================================")
    print()
    print(f"  Clients should set:")
    print(f"  OBSCURA_REGISTRY_URL=http://<this-server-ip>:{args.port}")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[registry] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
