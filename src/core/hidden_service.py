"""Obscura hidden-service host.

Runs inside its own process. Given a local TCP target and a service keypair,
establishes onion circuits to several intro points, publishes a signed
descriptor to the registry, and bridges incoming rendezvous sessions to
the local target.

Role split (Tor v3 style):

- Intro points: N relays the host holds open circuits to. Each intro
  point advertises the service to clients via the descriptor. When a
  client introduces, the intro point relays a sealed blob to the host
  but never carries session data. Introduce blobs are encrypted to the
  service pubkey so the intro point can't read them.
- Rendezvous point: a separate relay chosen by the client. The host
  opens a fresh circuit to the rendezvous point per session and joins
  it by presenting the client's cookie. The rendezvous point splices
  the two circuits so hs_data flows between them.

Payload confidentiality: hs_data chunks are sealed with
onion_encrypt_for_peer so the rendezvous point only relays ciphertext.
Client→host uses the service pubkey; host→client uses the client's
ephemeral pubkey delivered inside the introduce blob.
"""

from __future__ import annotations

import base64
import json
import os
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


INTRO_POINT_COUNT = 3


class HiddenServiceHost:
    def __init__(self, target_host: str, target_port: int, key_path: str):
        self.target_host = target_host
        self.target_port = int(target_port)
        self.priv, self.pub_pem = ecc_load_or_create_keypair(key_path)
        self.address = address_from_pubkey(self.pub_pem)

        # Intro-circuit state: one circuit per intro point. Maps intro
        # request_id -> {'peer': peer_dict, 'route': [peer]}.
        self._intro_circuits: dict[str, dict[str, Any]] = {}
        self._intro_peers: list[dict[str, Any]] = []

        # Rendezvous session state:
        # rv_req_id (host's circuit to the rv point) -> {
        #   'sock': local TCP socket,
        #   'client_pub': PEM str, 'route': [rv_peer],
        #   'ready': threading.Event(),
        # }
        self._sessions: dict[str, dict[str, Any]] = {}
        self._sessions_lock = threading.Lock()

        self._stopped = threading.Event()

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
        if typ == 'hs_introduce':
            self._handle_introduce(inner)
        elif typ == 'rv_ready':
            self._handle_rv_ready(inner)
        elif typ == 'hs_data':
            self._handle_data(inner)
        elif typ == 'hs_close':
            self._handle_close(inner)

    # ── Intro → rendezvous ────────────────────────────────────────

    def _handle_introduce(self, inner: dict):
        """An intro point forwarded a client's sealed introduce blob."""
        blob = inner.get('introduce_payload')
        if not blob:
            return
        payload_json = onion_decrypt_with_priv(self.priv, blob)
        if not payload_json:
            log.warning("Host: introduce blob decrypt failed")
            return
        try:
            payload = json.loads(payload_json)
        except Exception:
            return
        rv_point = payload.get('rv_point')
        cookie = payload.get('cookie')
        client_pub = payload.get('client_pub')
        if not rv_point or not cookie or not client_pub:
            log.warning("Host: malformed introduce payload")
            return

        threading.Thread(
            target=self._open_rv_session,
            args=(rv_point, cookie, client_pub),
            daemon=True,
        ).start()

    def _open_rv_session(self, rv_point: dict, cookie: str, client_pub: str):
        rv_req_id = f"R{time.time_ns()}"
        route = [rv_point]
        ready = threading.Event()
        with self._sessions_lock:
            self._sessions[rv_req_id] = {
                'sock': None,
                'client_pub': client_pub,
                'route': route,
                'ready': ready,
            }

        envelope = {
            'type': 'rv_join',
            'request_id': rv_req_id,
            'cookie': cookie,
            'pub': self.pub_pem,
        }
        if not send_hs_frame(route, envelope):
            log.warning("rv_join send failed for session %s", rv_req_id)
            self._drop_session(rv_req_id)
            return

        # Wait for the rendezvous to confirm the splice before dialling local.
        if not ready.wait(timeout=10):
            log.warning("rv_ready not received for session %s", rv_req_id)
            self._drop_session(rv_req_id)
            return

        try:
            sock = socket.create_connection(
                (self.target_host, self.target_port), timeout=5)
        except Exception as e:
            log.error("Host: local target connect failed | %s", e)
            self._send_close(rv_req_id)
            self._drop_session(rv_req_id)
            return

        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
            if entry is None:
                try:
                    sock.close()
                except Exception:
                    pass
                return
            entry['sock'] = sock

        log.info("HS session %s → local %s:%s",
                 rv_req_id, self.target_host, self.target_port)
        threading.Thread(
            target=self._pump_local_to_circuit,
            args=(rv_req_id, sock),
            daemon=True,
        ).start()

    def _handle_rv_ready(self, inner: dict):
        rv_req_id = inner.get('request_id')
        if not rv_req_id:
            return
        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
        if entry:
            entry['ready'].set()

    # ── Data plane on rv circuits ─────────────────────────────────

    def _handle_data(self, inner: dict):
        rv_req_id = inner.get('request_id')
        sealed = inner.get('chunk')
        if not rv_req_id or not sealed:
            return
        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
        if not entry or not entry.get('sock'):
            return
        chunk_b64 = onion_decrypt_with_priv(self.priv, sealed)
        if chunk_b64 is None:
            log.warning("HS chunk decrypt failed session=%s", rv_req_id)
            return
        try:
            entry['sock'].sendall(base64.b64decode(chunk_b64))
        except Exception as e:
            log.warning("HS local write error session=%s | %s", rv_req_id, e)
            self._close_session(rv_req_id, notify=True)

    def _handle_close(self, inner: dict):
        rv_req_id = inner.get('request_id')
        if rv_req_id:
            self._close_session(rv_req_id, notify=False)

    def _close_session(self, rv_req_id: str, *, notify: bool):
        with self._sessions_lock:
            entry = self._sessions.pop(rv_req_id, None)
        if entry and entry.get('sock'):
            try:
                entry['sock'].close()
            except Exception:
                pass
        if notify:
            self._send_close(rv_req_id)

    def _drop_session(self, rv_req_id: str):
        with self._sessions_lock:
            self._sessions.pop(rv_req_id, None)

    def _pump_local_to_circuit(self, rv_req_id: str, sock: socket.socket):
        try:
            while not self._stopped.is_set():
                chunk = sock.recv(8192)
                if not chunk:
                    break
                self._send_data(rv_req_id, chunk)
        except Exception as e:
            log.warning("HS pump error session=%s | %s", rv_req_id, e)
        finally:
            self._close_session(rv_req_id, notify=True)

    def _send_data(self, rv_req_id: str, chunk: bytes):
        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
        if not entry:
            return
        sealed = onion_encrypt_for_peer(
            entry['client_pub'], base64.b64encode(chunk).decode())
        envelope = {
            'type': 'hs_data',
            'request_id': rv_req_id,
            'chunk': sealed,
        }
        send_hs_frame(entry['route'], envelope)

    def _send_close(self, rv_req_id: str):
        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
        if not entry:
            return
        envelope = {
            'type': 'hs_close',
            'request_id': rv_req_id,
        }
        send_hs_frame(entry['route'], envelope)

    # ── Startup ───────────────────────────────────────────────────

    def _pick_intro_points(self, peers: list[dict], count: int) -> list[dict]:
        candidates = [p for p in peers if p.get('role') == 'node' and p.get('pub')]
        if not candidates:
            return []
        random.shuffle(candidates)
        return candidates[:count]

    def establish(self, peers: list[dict] | None = None) -> bool:
        """Open intro circuits to several relays so clients have a choice."""
        if peers is None:
            peers = fetch_peers_from_registry()
        intros = self._pick_intro_points(peers, INTRO_POINT_COUNT)
        if not intros:
            log.error("No suitable intro points among peers")
            return False

        established = 0
        for peer in intros:
            req_id = f"H{time.time_ns()}"
            route = [peer]
            envelope = {
                'type': 'hs_establish',
                'request_id': req_id,
                'service_addr': self.address,
                'pub': self.pub_pem,
            }
            if send_hs_frame(route, envelope):
                self._intro_circuits[req_id] = {'peer': peer, 'route': route}
                self._intro_peers.append(peer)
                established += 1
                log.info("HS %s established at intro %s:%s",
                         self.address, peer.get('host'), peer.get('port'))
            else:
                log.warning("Intro establish failed at %s:%s",
                            peer.get('host'), peer.get('port'))

        return established > 0

    def publish_descriptor(self) -> bool:
        if not self._intro_peers:
            return False
        intro = [{
            'host': p.get('host'),
            'port': p.get('port'),
            'ws_port': p.get('ws_port'),
            'pub': p.get('pub'),
        } for p in self._intro_peers]
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
            log.info("Descriptor published for %s (%d intros)",
                     self.address, len(intro))
            return True
        except Exception as e:
            log.error("Failed to publish descriptor: %s", e)
            return False

    def run(self):
        set_reverse_frame_callback(self._on_tcp_reverse)
        set_proxy_ws_client(self.ws_client)

        if not self.establish():
            return False
        if not self.publish_descriptor():
            return False

        log.info("Hidden service %s serving → %s:%s",
                 self.address, self.target_host, self.target_port)

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
