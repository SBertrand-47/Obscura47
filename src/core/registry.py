"""
Obscura47 Bootstrap Registry Server

A lightweight HTTP server that nodes register with so peers can discover
each other over the internet — not just the local network.

Run standalone:  python -m src.core.registry
Or host on any public server.
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from src.utils.config import REGISTRY_PORT, REGISTRY_PEER_TTL


# In-memory peer store: key = "host:port" → peer dict
_peers: dict[str, dict] = {}
_lock = threading.Lock()


def _expire():
    """Remove peers that haven't sent a heartbeat within TTL."""
    cutoff = time.time() - REGISTRY_PEER_TTL
    with _lock:
        expired = [k for k, v in _peers.items() if v.get("ts", 0) < cutoff]
        for k in expired:
            del _peers[k]


def _expire_loop():
    while True:
        time.sleep(15)
        _expire()


class _Handler(BaseHTTPRequestHandler):
    """Minimal JSON API:
       POST /register  — node announces itself
       GET  /peers     — get list of all live peers
    """

    def log_message(self, fmt, *args):
        # Quieter logging
        print(f"[registry] {args[0]}")

    # ── GET /peers ────────────────────────────────────────────────
    def do_GET(self):
        if self.path == "/peers":
            _expire()
            with _lock:
                body = json.dumps(list(_peers.values())).encode()
            self._respond(200, body)
        else:
            self._respond(404, b'{"error":"not found"}')

    # ── POST /register ────────────────────────────────────────────
    def do_POST(self):
        if self.path == "/register":
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                data = json.loads(raw)

                role = data.get("role")       # "node" | "exit" | "proxy"
                port = int(data.get("port"))
                pub  = data.get("pub")        # optional PEM public key

                # Use the IP the request actually came from (internet IP)
                host = self.client_address[0]

                key = f"{host}:{port}"
                peer = {
                    "host": host,
                    "port": port,
                    "role": role,
                    "ts":   time.time(),
                }
                if pub:
                    peer["pub"] = pub

                with _lock:
                    _peers[key] = peer

                print(f"[registry] Registered {role} at {key}")
                self._respond(200, json.dumps({"ok": True, "your_ip": host}).encode())

            except Exception as e:
                self._respond(400, json.dumps({"error": str(e)}).encode())
        else:
            self._respond(404, b'{"error":"not found"}')

    def _respond(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_registry(host="0.0.0.0", port=None):
    """Start the bootstrap registry server."""
    port = port or REGISTRY_PORT
    threading.Thread(target=_expire_loop, daemon=True).start()
    server = HTTPServer((host, port), _Handler)
    print(f"[registry] Obscura47 bootstrap registry listening on {host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_registry()
