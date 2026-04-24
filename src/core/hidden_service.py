"""Obscura hidden-service host.

Runs inside its own process. Given a local TCP target and a service keypair,
establishes an onion circuit to a meeting-point relay, publishes a signed
descriptor to the registry, and bridges incoming onion sessions to the
local target.

v1 simplifications:
- Single meeting point per service (Tor v3 uses 3 for DoS resistance).
- Meeting point splices intro + rendezvous in one relay.

Payload confidentiality: hs_data chunks between client and host are
sealed with onion_encrypt_for_peer so the meeting point only sees
opaque ciphertext. Client→host uses the service pubkey (from the
descriptor); host→client uses the client's ephemeral pubkey handed to
the host in hs_incoming.
"""

from __future__ import annotations

import base64
import json
import random
import socket
import threading
import time
import urllib.request
from typing import Any

from src.core.encryptions import (
    ecc_load_or_create_keypair,
    onion_decrypt_with_priv,
    onion_encrypt_for_peer,
)
from src.core.router import (
    _send_frame_via_route,
    send_hs_frame,
    set_proxy_ws_client,
    set_reverse_frame_callback,
)
from src.core.ws_transport import WSClient
from src.core.internet_discovery import fetch_peers_from_registry
from src.utils.config import (
    REGISTRY_URL,
    CHANNEL_QUEUE_MAX,
    CHANNEL_IDLE_CLOSE_SECONDS,
    TLS_VERIFY,
)
from src.utils.logger import get_logger
from src.utils.onion_addr import (
    address_from_pubkey,
    build_descriptor,
    DESCRIPTOR_TTL,
)

log = get_logger(__name__)


class HiddenServiceHost:
    def __init__(self, target_host: str, target_port: int, key_path: str):
        self.target_host = target_host
        self.target_port = int(target_port)
        self.priv, self.pub_pem = ecc_load_or_create_keypair(key_path)
        self.address = address_from_pubkey(self.pub_pem)

        # Intro-circuit state — single meeting point for v1.
        self.meeting_point: dict[str, Any] | None = None
        self.intro_route: list[dict] | None = None
        self.intro_request_id: str | None = None

        # session_id -> (local TCP socket, client_pub PEM) for the target app.
        # client_pub is used to seal host→client hs_data so the meeting point
        # can't observe payloads.
        self._sessions: dict[str, tuple[socket.socket, str]] = {}
        self._sessions_lock = threading.Lock()

        self._stopped = threading.Event()

        # Host owns its own WSClient so reverse frames flow through our handler.
        self.ws_client = WSClient(
            self.priv, self.pub_pem,
            queue_max=CHANNEL_QUEUE_MAX,
            idle_close_seconds=CHANNEL_IDLE_CLOSE_SECONDS,
            tls_verify=TLS_VERIFY,
            on_receive=self._on_ws_message,
        )

    # ── Reverse-frame handling ─────────────────────────────────────

    def _on_ws_message(self, message):
        try:
            frame = json.loads(message) if isinstance(message, str) else message
        except Exception:
            return
        if isinstance(frame, dict) and frame.get('type') in ('reverse_data', 'reverse_close'):
            self._handle_reverse(frame)

    def _on_tcp_reverse(self, frame: dict):
        self._handle_reverse(frame)

    def _handle_reverse(self, frame: dict):
        """Decrypt the inner HS payload and dispatch to the right session handler."""
        encrypted = frame.get('encrypted_response')
        if not encrypted:
            return
        inner_json = onion_decrypt_with_priv(self.priv, encrypted)
        if not inner_json:
            log.warning("Host: failed to decrypt reverse frame")
            return
        try:
            inner = json.loads(inner_json)
        except Exception:
            return
        typ = inner.get('type')
        if typ == 'hs_incoming':
            self._handle_incoming(inner)
        elif typ == 'hs_data':
            self._handle_data(inner)
        elif typ == 'hs_close':
            self._handle_close(inner)

    def _handle_incoming(self, inner: dict):
        session_id = inner.get('session_id')
        client_pub = inner.get('client_pub')
        if not session_id or not client_pub:
            log.warning("Host: hs_incoming missing session_id or client_pub")
            return
        try:
            sock = socket.create_connection((self.target_host, self.target_port), timeout=5)
        except Exception as e:
            log.error("Host: failed to connect local target %s:%s | %s",
                      self.target_host, self.target_port, e)
            self._send_close(session_id)
            return
        with self._sessions_lock:
            self._sessions[session_id] = (sock, client_pub)
        log.info("HS session %s opened → local %s:%s",
                 session_id, self.target_host, self.target_port)
        threading.Thread(target=self._pump_local_to_circuit,
                         args=(session_id, sock), daemon=True).start()

    def _handle_data(self, inner: dict):
        session_id = inner.get('session_id')
        sealed = inner.get('chunk')
        if not session_id or not sealed:
            return
        with self._sessions_lock:
            entry = self._sessions.get(session_id)
        if not entry:
            return
        sock, _ = entry
        chunk_b64 = onion_decrypt_with_priv(self.priv, sealed)
        if chunk_b64 is None:
            log.warning("HS chunk decrypt failed session=%s", session_id)
            return
        try:
            sock.sendall(base64.b64decode(chunk_b64))
        except Exception as e:
            log.warning("HS local write error session=%s | %s", session_id, e)
            self._close_session(session_id, notify=True)

    def _handle_close(self, inner: dict):
        session_id = inner.get('session_id')
        if session_id:
            self._close_session(session_id, notify=False)

    def _close_session(self, session_id: str, *, notify: bool):
        with self._sessions_lock:
            entry = self._sessions.pop(session_id, None)
        if entry:
            sock, _ = entry
            try:
                sock.close()
            except Exception:
                pass
        if notify:
            self._send_close(session_id)

    def _pump_local_to_circuit(self, session_id: str, sock: socket.socket):
        """Read from the local app socket and send as hs_data along the intro circuit."""
        try:
            while not self._stopped.is_set():
                chunk = sock.recv(8192)
                if not chunk:
                    break
                self._send_data(session_id, chunk)
        except Exception as e:
            log.warning("HS pump error session=%s | %s", session_id, e)
        finally:
            self._close_session(session_id, notify=True)

    # ── Outbound on the intro circuit ──────────────────────────────

    def _send_data(self, session_id: str, chunk: bytes):
        if not self.intro_route or not self.intro_request_id:
            return
        with self._sessions_lock:
            entry = self._sessions.get(session_id)
        if not entry:
            return
        _, client_pub = entry
        sealed = onion_encrypt_for_peer(client_pub, base64.b64encode(chunk).decode())
        envelope = {
            'type': 'hs_data',
            'request_id': self.intro_request_id,
            'session_id': session_id,
            'chunk': sealed,
        }
        send_hs_frame(self.intro_route, envelope)

    def _send_close(self, session_id: str):
        if not self.intro_route or not self.intro_request_id:
            return
        envelope = {
            'type': 'hs_close',
            'request_id': self.intro_request_id,
            'session_id': session_id,
        }
        send_hs_frame(self.intro_route, envelope)

    # ── Startup ───────────────────────────────────────────────────

    def _pick_meeting_point(self, peers: list[dict]) -> dict | None:
        candidates = [p for p in peers if p.get('role') == 'node' and p.get('pub')]
        return random.choice(candidates) if candidates else None

    def establish(self, peers: list[dict] | None = None) -> bool:
        """Build an intro circuit to a meeting point and register with it."""
        if peers is None:
            peers = fetch_peers_from_registry()
        mp = self._pick_meeting_point(peers)
        if not mp:
            log.error("No suitable meeting point among peers")
            return False
        # Single-hop circuit for v1: meeting point *is* the terminal.
        # Multi-hop can be layered on later by padding with extra relays.
        self.meeting_point = mp
        self.intro_route = [mp]
        self.intro_request_id = f"H{time.time_ns()}"
        envelope = {
            'type': 'hs_establish',
            'request_id': self.intro_request_id,
            'service_addr': self.address,
            'pub': self.pub_pem,
        }
        ok = send_hs_frame(self.intro_route, envelope)
        if ok:
            log.info("HS %s established at meeting point %s:%s",
                     self.address, mp.get('host'), mp.get('port'))
        return bool(ok)

    def publish_descriptor(self) -> bool:
        """Publish a signed descriptor listing our meeting point."""
        if not self.meeting_point:
            return False
        intro = [{
            'host': self.meeting_point.get('host'),
            'port': self.meeting_point.get('port'),
            'ws_port': self.meeting_point.get('ws_port'),
            'pub': self.meeting_point.get('pub'),
        }]
        desc = build_descriptor(
            self.priv, self.pub_pem,
            port=self.target_port,
            intro_points=intro,
            ttl=DESCRIPTOR_TTL,
        )
        body = json.dumps(desc).encode()
        req = urllib.request.Request(
            f"{REGISTRY_URL}/hs/descriptor",
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            log.info("Descriptor published for %s", self.address)
            return True
        except Exception as e:
            log.error("Failed to publish descriptor: %s", e)
            return False

    def run(self):
        # Register global reverse-frame callback so TCP tunnel readers
        # dispatch inbound reverse frames to this host.
        set_reverse_frame_callback(self._on_tcp_reverse)
        set_proxy_ws_client(self.ws_client)

        if not self.establish():
            return False
        if not self.publish_descriptor():
            return False

        log.info("Hidden service %s serving → %s:%s",
                 self.address, self.target_host, self.target_port)

        # Periodic re-publish so the descriptor doesn't expire.
        def republish_loop():
            while not self._stopped.is_set():
                time.sleep(max(60, DESCRIPTOR_TTL // 2))
                if self._stopped.is_set():
                    break
                self.publish_descriptor()
        threading.Thread(target=republish_loop, daemon=True).start()

        try:
            while not self._stopped.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._stopped.set()
        return True


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Obscura hidden service host")
    parser.add_argument('--target', default='127.0.0.1:8000',
                        help='local TCP target, host:port (default 127.0.0.1:8000)')
    parser.add_argument('--key', default='hs_service.pem',
                        help='path to service keypair (PEM); created if missing')
    args = parser.parse_args()

    host_str, port_str = args.target.rsplit(':', 1)
    host = HiddenServiceHost(host_str, int(port_str), args.key)
    print(f"[hs] address = {host.address}")
    host.run()


if __name__ == '__main__':
    main()
