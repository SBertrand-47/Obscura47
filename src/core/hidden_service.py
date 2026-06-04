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

from src.utils import diag
from src.core.encryptions import (
    ecc_load_or_create_keypair,
    onion_decrypt_with_priv,
    onion_encrypt_for_peer,
)
from src.core import peer_health
from src.core.router import (
    build_hs_route,
    send_hs_frame,
    set_proxy_ws_client,
    set_reverse_frame_callback,
)
from src.core.ws_transport import WSClient
from src.core.internet_discovery import (
    fetch_peers_from_registry,
    learn_public_ip,
    registry_request_json,
    RegistryHTTPError,
)
from src.utils.config import (
    REGISTRY_URL,
    CHANNEL_QUEUE_MAX,
    CHANNEL_IDLE_CLOSE_SECONDS,
    HS_CIRCUIT_HOPS,
    TLS_VERIFY,
)
from src.utils.identity import register_caller, unregister_caller
from src.utils.logger import get_logger
from src.utils.onion_addr import (
    address_from_pubkey,
    build_descriptor,
    DESCRIPTOR_REPUBLISH_INTERVAL,
    DESCRIPTOR_TTL,
)

log = get_logger(__name__)


INTRO_POINT_COUNT = 3

# How long establish() waits for an intro point to confirm (ack) that it
# registered the service before the host will advertise that intro in its
# descriptor. A fire-and-forget send only proves the frame reached the first
# relay, not that the intro point is actually reachable through the circuit -
# the ack closes that gap so a host never publishes an intro it can't use.
INTRO_ACK_TIMEOUT = 6.0


def _post_descriptor_delete(address: str, priv) -> bool:
    """Sign ``hs-delete:{addr}:{ts}`` and ask the registry to drop the
    descriptor for ``address``. Returns True on success. Best-effort."""
    from src.core.encryptions import ecdsa_sign
    timestamp = time.time()
    message = f"hs-delete:{address}:{timestamp}".encode()
    try:
        signature = ecdsa_sign(priv, message)
    except Exception as e:
        log.warning("HS descriptor delete signature failed for %s: %s", address, e)
        return False
    body = json.dumps({
        "addr": address,
        "timestamp": timestamp,
        "signature": signature,
    }).encode()
    try:
        registry_request_json(
            f"{REGISTRY_URL}/hs/descriptor/delete",
            method='POST',
            data=body,
            extra_headers={'Content-Type': 'application/json'},
            timeout=5,
        )
        log.info("Descriptor deleted from registry for %s", address)
        diag.emit("desc_delete", addr=address, ok=True)
        return True
    except Exception as e:
        log.warning("Failed to delete descriptor for %s: %s", address, e)
        diag.emit("desc_delete", addr=address, ok=False, err=str(e))
        return False


def withdraw_descriptor_by_name(name: str) -> bool:
    """Withdraw the registry descriptor for a locally-hosted site by name.

    Loads the site's key, derives its address, and posts a signed delete so the
    site stops appearing in discovery. Returns False if the site is unknown or
    the request fails (best-effort; never raises)."""
    try:
        from src.utils.sites import list_sites
        from src.core.encryptions import ecc_load_or_create_keypair
        info = next((s for s in list_sites() if s.name == name), None)
        if info is None or not info.key_path:
            return False
        priv, _ = ecc_load_or_create_keypair(info.key_path)
    except Exception as e:
        log.warning("withdraw_descriptor_by_name(%s) failed to load key: %s",
                    name, e)
        return False
    return _post_descriptor_delete(info.address, priv)


class HiddenServiceHost:
    def __init__(self, target_host: str, target_port: int, key_path: str):
        self.target_host = target_host
        self.target_port = int(target_port)
        self.priv, self.pub_pem = ecc_load_or_create_keypair(key_path)
        self.address = address_from_pubkey(self.pub_pem)

        # Intro-circuit state: one circuit per intro point. Maps intro
        # request_id -> {'peer': peer_dict, 'route': [peer...]}.
        self._intro_circuits: dict[str, dict[str, Any]] = {}
        self._intro_peers: list[dict[str, Any]] = []
        # Relay pool used to pad both intro and rv circuits with middle hops.
        self._relay_pool: list[dict[str, Any]] = []

        # Pending intro-establish acks: req_id -> Event, set when the intro
        # point confirms it registered the service. establish() waits on these
        # so it only publishes intros the intro point actually acknowledged.
        self._intro_acks: dict[str, threading.Event] = {}
        self._intro_acks_lock = threading.Lock()

        # Rendezvous session state:
        # rv_req_id (host's circuit to the rv point) -> {
        #   'sock': local TCP socket,
        #   'client_pub': PEM str, 'route': [rv_peer],
        #   'ready': threading.Event(),
        # }
        self._sessions: dict[str, dict[str, Any]] = {}
        self._sessions_lock = threading.Lock()

        self._stopped = threading.Event()
        diag.set_role("host")
        diag.set_node_id(self.address)

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
        if typ == 'hs_establish_ack':
            self._handle_establish_ack(inner)
        elif typ == 'hs_introduce':
            self._handle_introduce(inner)
        elif typ == 'rv_ready':
            self._handle_rv_ready(inner)
        elif typ == 'hs_data':
            self._handle_data(inner)
        elif typ == 'hs_close':
            self._handle_close(inner)

    def _handle_establish_ack(self, inner: dict):
        """An intro point confirmed it registered our service for a circuit.

        Wakes the establish() waiter for this request_id so that intro can be
        published. An intro whose circuit never reaches a live intro point
        never produces this ack, so it is left out of the descriptor."""
        req_id = inner.get('request_id')
        if not req_id:
            return
        with self._intro_acks_lock:
            ev = self._intro_acks.get(req_id)
        if ev is not None:
            ev.set()

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

        log.info(
            "Host: introduce received for %s | rv_point=%s:%s cookie=%s…",
            self.address,
            rv_point.get('host'), rv_point.get('port'),
            (cookie or '')[:8],
        )

        threading.Thread(
            target=self._open_rv_session,
            args=(rv_point, cookie, client_pub),
            daemon=True,
        ).start()

    def _open_rv_session(self, rv_point: dict, cookie: str, client_pub: str):
        rv_req_id = f"R{time.time_ns()}"
        route = build_hs_route(self._relay_pool, rv_point, HS_CIRCUIT_HOPS)
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
            log.warning(
                "rv_join send failed for session %s | rv_point=%s:%s",
                rv_req_id, rv_point.get('host'), rv_point.get('port'),
            )
            self._drop_session(rv_req_id)
            return

        # Wait for the rendezvous to confirm the splice before dialling local.
        if not ready.wait(timeout=10):
            from src.core.internet_discovery import is_public_internet_host
            extra = ""
            if not is_public_internet_host(rv_point.get('host')):
                extra = (
                    f" | rv_point {rv_point.get('host')} is on a private "
                    "network and is unreachable from this host"
                )
            log.warning(
                "rv_ready not received for session %s | rv_point=%s:%s%s",
                rv_req_id, rv_point.get('host'), rv_point.get('port'), extra,
            )
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

        local_addr = sock.getsockname()[:2]
        register_caller(local_addr, client_pub)

        with self._sessions_lock:
            entry = self._sessions.get(rv_req_id)
            if entry is None:
                unregister_caller(local_addr)
                try:
                    sock.close()
                except Exception:
                    pass
                return
            entry['sock'] = sock
            entry['local_addr'] = local_addr

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
        if entry:
            local_addr = entry.get('local_addr')
            if local_addr is not None:
                unregister_caller(local_addr)
            sock = entry.get('sock')
            if sock is not None:
                try:
                    sock.close()
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
        from src.core.internet_discovery import (
            is_self_peer, is_private_peer, is_public_internet_host, allow_lan_peers,
        )
        lan_ok = allow_lan_peers()
        candidates = [
            p for p in peers
            if p.get('role') == 'node' and p.get('pub')
            and not is_self_peer(p)
            and (lan_ok or not is_private_peer(p))
        ]
        if not candidates:
            # All public nodes are filtered (self or LAN-only) - fall back
            # so the host can still publish an intro. The dialer will fail
            # to reach it, but the diagnose path surfaces that explicitly
            # so we prefer the warning over silent unreachability.
            log.warning(
                "HS %s: no externally-reachable intro candidates "
                "(self-filter or RFC1918); falling back to any node",
                getattr(self, 'address', '?'),
            )
            candidates = [p for p in peers if p.get('role') == 'node' and p.get('pub')]
        if not candidates:
            return []
        # Reachability gate: a candidate that looks fine on paper (public IP,
        # not self, registered in the registry) might still be unreachable
        # from this host - common case is a dual-stack VPS that registered
        # both its IPv4 and IPv6 address, and we have no IPv6 default route.
        # Publishing such a peer as an intro silently strands every client
        # dial. Skip candidates whose WS port doesn't accept TCP within 3s.
        reachable: list[dict] = []
        for p in candidates:
            ws_port = p.get('ws_port')
            host = p.get('host')
            if not (ws_port and host):
                # No WS port means we can neither probe its reachability nor
                # maintain an intro circuit to it - publishing it as an intro
                # strands every client dial. (A gateway peer registered without
                # a ws_port did exactly this: it bypassed the probe below and
                # got advertised as a dead intro.) Exclude it.
                log.info("HS skip intro candidate %s: no ws_port to verify or "
                         "maintain an intro circuit", host or p.get('port'))
                continue
            # Always probe - the probe is the source of truth for
            # reachability. Skipping just because peer_health is in
            # cooldown would let one transient failure black-hole
            # an otherwise-fine peer for 120s, and on small networks
            # that means the host has nothing left to publish.
            ok, why = peer_health.probe_tcp(host, int(ws_port), timeout=3.0)
            if ok:
                # mark_success clears any prior cooldown so the rest
                # of the system stops avoiding this peer too.
                peer_health.mark_success(host, int(ws_port))
            else:
                peer_health.mark_failure(host, int(ws_port),
                                         reason=f"host intro probe: {why}")
                log.info("HS skip intro candidate %s:%s (probe failed: %s)",
                         host, p.get('port'), why)
                continue
            reachable.append(p)
        if not reachable:
            log.warning(
                "HS %s: every intro candidate failed reachability probe - "
                "publishing nothing this cycle. Check that at least one "
                "registered node is reachable on its WS port from this host.",
                getattr(self, 'address', '?'),
            )
            return []
        # Prefer publicly-routable intros so clients on any network can
        # reach them. Fall back to private-IP relays only to fill the
        # quota if there aren't enough public ones.
        random.shuffle(reachable)
        public = [p for p in reachable if is_public_internet_host(p.get('host'))]
        private = [p for p in reachable if not is_public_internet_host(p.get('host'))]
        chosen = (public + private)[:count]
        if not public:
            log.warning(
                "No publicly-routable intro candidates; using private-IP relays. "
                "Off-LAN clients will not be able to introduce.",
            )
        return chosen

    def establish(self, peers: list[dict] | None = None,
                  *, refresh: bool = False) -> bool:
        """Open intro circuits to several relays so clients have a choice.

        When ``refresh=True``, drop any previously-tracked intro circuits
        first - used by the republish loop to keep WS connections warm
        (the WS pool idle-closes connections after a minute, which would
        otherwise sever the intro channel and silently strand the host).
        """
        if peers is None:
            peers = fetch_peers_from_registry()
        self._relay_pool = [p for p in peers if p.get('pub')]
        intros = self._pick_intro_points(self._relay_pool, INTRO_POINT_COUNT)
        if not intros:
            log.error("No suitable intro points among peers")
            # On a refresh, keep the last-known-good intro set so the
            # republish loop can still re-publish the existing descriptor.
            # Wiping it on one bad cycle (common when the node "goes cold"
            # or a stop/restart momentarily drains the small relay pool)
            # would strand the descriptor and let it expire into a 404.
            return bool(self._intro_peers) if refresh else False

        # Send an establish to each candidate, then wait for the intro point
        # to ACK that it registered the service. A successful send only proves
        # the frame reached the first relay - not that it traversed the circuit
        # to a live intro point. Publishing on send alone advertises intros the
        # host can't actually use (a client then reads the descriptor, dials
        # that dead intro, and the rendezvous fails). The ack closes that gap.
        #
        # Two tiers of result are tracked: `acked_*` (the intro point
        # confirmed - the set we want to publish) and `sent_*` (the send
        # succeeded but no ack arrived - a fallback used only if nothing acks,
        # e.g. against older relays that don't send acks, so a host is never
        # stranded by the stricter rule).
        acked_circuits: dict[str, dict[str, Any]] = {}
        acked_peers: list[dict[str, Any]] = []
        sent_circuits: dict[str, dict[str, Any]] = {}
        sent_peers: list[dict[str, Any]] = []
        pending: list[tuple[str, dict, list, threading.Event]] = []
        for peer in intros:
            req_id = f"H{time.time_ns()}"
            route = build_hs_route(self._relay_pool, peer, HS_CIRCUIT_HOPS)
            envelope = {
                'type': 'hs_establish',
                'request_id': req_id,
                'service_addr': self.address,
                'pub': self.pub_pem,
            }
            ev = threading.Event()
            with self._intro_acks_lock:
                self._intro_acks[req_id] = ev
            if send_hs_frame(route, envelope):
                sent_circuits[req_id] = {'peer': peer, 'route': route}
                sent_peers.append(peer)
                pending.append((req_id, peer, route, ev))
                log.info("HS %s sent establish to intro %s:%s via %d hop(s); "
                         "awaiting ack", self.address, peer.get('host'),
                         peer.get('port'), len(route))
            else:
                with self._intro_acks_lock:
                    self._intro_acks.pop(req_id, None)
                log.warning("Intro establish send failed at %s:%s",
                            peer.get('host'), peer.get('port'))

        # Wait for acks up to a shared deadline. Acks arrive concurrently on
        # the reverse channel, so a per-entry wait against one deadline lets
        # them all land within INTRO_ACK_TIMEOUT total.
        deadline = time.time() + INTRO_ACK_TIMEOUT
        for req_id, peer, route, ev in pending:
            if ev.wait(max(0.0, deadline - time.time())):
                acked_circuits[req_id] = {'peer': peer, 'route': route}
                acked_peers.append(peer)
                log.info("HS %s intro confirmed at %s:%s",
                         self.address, peer.get('host'), peer.get('port'))
            else:
                log.warning("HS %s intro at %s:%s did not confirm within %.0fs; "
                            "excluding it from the descriptor", self.address,
                            peer.get('host'), peer.get('port'), INTRO_ACK_TIMEOUT)
            with self._intro_acks_lock:
                self._intro_acks.pop(req_id, None)

        if acked_peers:
            # The intended path: publish only intros the intro point confirmed.
            self._intro_circuits = acked_circuits
            self._intro_peers = acked_peers
            return True

        # Nothing confirmed this cycle.
        if refresh and self._intro_peers:
            # Keep the last confirmed intro set alive rather than swapping to
            # unconfirmed peers - the existing descriptor still works.
            log.info("HS %s: no new intro confirmations; keeping existing intros",
                     self.address)
            return True
        if sent_peers:
            # Initial publish with no acks at all - likely relays on an older
            # build that don't ack. Fall back to the send-succeeded set so the
            # descriptor isn't empty (no regression vs. the old behaviour).
            log.warning("HS %s: no intro confirmations; publishing %d "
                        "unconfirmed intro(s)", self.address, len(sent_peers))
            self._intro_circuits = sent_circuits
            self._intro_peers = sent_peers
            return True

        log.warning("HS %s established no intro points this cycle", self.address)
        return bool(self._intro_peers) if refresh else False

    def delete_descriptor(self) -> bool:
        """Tell the registry to drop our descriptor immediately.

        Without this, a stopped HS lingers for DESCRIPTOR_TTL (1 hour) and
        clients keep dialing dead intro points. Signs ``hs-delete:{addr}:{ts}``
        with the service key; the registry verifies against the stored
        descriptor's pubkey before deleting.
        """
        return _post_descriptor_delete(self.address, self.priv)

    def stop(self):
        """Trigger graceful shutdown: stop loops and purge descriptor.

        Idempotent on the registry-delete side (registry treats a missing
        descriptor as a no-op success) so calling stop() multiple times via
        atexit + an explicit caller is safe.
        """
        self._stopped.set()
        try:
            self.delete_descriptor()
        except Exception as e:
            log.warning("delete_descriptor during stop failed: %s", e)

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
        try:
            reply = registry_request_json(
                f"{REGISTRY_URL}/hs/descriptor",
                method='POST',
                data=body,
                extra_headers={'Content-Type': 'application/json'},
                timeout=10,
            )
        except RegistryHTTPError as e:
            if e.kind == "content_type":
                log.error(
                    "Descriptor publish for %s rejected non-JSON response (%s). "
                    "The deployed registry is likely missing the /hs/descriptor "
                    "endpoint - redeploy registry_server.py.",
                    self.address, e.content_type,
                )
            else:
                log.error("Failed to publish descriptor for %s [%s]: %s",
                          self.address, e.kind, e)
            return False
        # Confirm the registry actually stored what we sent. A 2xx with the
        # wrong addr (or missing expires) means a future fetch will 404 even
        # though publish "succeeded" - log it loudly instead of silently
        # claiming success.
        if not isinstance(reply, dict) or reply.get("addr") != self.address \
                or "expires" not in reply:
            log.error(
                "Descriptor publish for %s returned unexpected body %r - "
                "treating as failure",
                self.address, reply,
            )
            return False
        log.info("Descriptor published for %s (%d intros)",
                 self.address, len(intro))
        diag.emit("desc_publish", addr=self.address, intros=len(intro))
        return True

    def run(self):
        set_reverse_frame_callback(self._on_tcp_reverse)
        set_proxy_ws_client(self.ws_client)

        # Learn our public IP before picking intros. A host whose machine
        # also runs a node ends up sharing the registry entry for that
        # WAN IP with any colocated/sibling-NAT machine; without this
        # call, the host can't recognise itself in the peer list and
        # ends up publishing its own WAN IP as an intro point - which
        # has no port forward and silently strands every client dial.
        learn_public_ip()

        # Belt-and-suspenders backstop: even if the caller forgets stop(),
        # interpreter shutdown still purges our descriptor so clients don't
        # keep dialing for an hour.
        import atexit as _atexit
        _atexit.register(self.delete_descriptor)

        # Try to publish immediately, but don't exit on a cold start: a
        # registry/relay hiccup at boot shouldn't kill the host (systemd
        # won't restart a clean exit), so fall through to the republish
        # loop, which retries quickly until it succeeds.
        if self.establish() and self.publish_descriptor():
            log.info("Hidden service %s serving → %s:%s",
                     self.address, self.target_host, self.target_port)
        else:
            log.warning("HS %s could not publish at startup; the republish "
                        "loop will keep retrying", self.address)

        def republish_loop():
            # Steady-state cadence: refresh more often than
            # CHANNEL_IDLE_CLOSE_SECONDS so the intro WS connections stay
            # warm - if they idle-close, the descriptor still points at the
            # relay but introduces have no path back and dials silently time
            # out. Capped below the idle window regardless of the configured
            # interval.
            from src.utils.config import CHANNEL_IDLE_CLOSE_SECONDS
            steady = max(20, min(DESCRIPTOR_REPUBLISH_INTERVAL,
                                 int(CHANNEL_IDLE_CLOSE_SECONDS) - 10))
            delay = steady
            backoff = 5
            while not self._stopped.is_set():
                for _ in range(int(delay)):
                    if self._stopped.is_set():
                        return
                    time.sleep(1)
                if self._stopped.is_set():
                    return
                ok = self.establish(refresh=True) and self.publish_descriptor()
                if ok:
                    delay = steady
                    backoff = 5
                else:
                    # Retry fast (then back off) so a transient failure can't
                    # leave the descriptor stale long enough to expire → 404.
                    delay = backoff
                    backoff = min(backoff * 2, steady)
                    log.warning("HS %s republish failed; retrying in %ds",
                                self.address, delay)
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
    from src.utils.sites import load_or_create_site_key
    parser = argparse.ArgumentParser(description="Obscura hidden service host")
    parser.add_argument('--target', default='127.0.0.1:8000',
                        help='local TCP target, host:port (default 127.0.0.1:8000)')
    parser.add_argument('--name', default=None,
                        help='site name under ~/.obscura47/sites (default "default")')
    parser.add_argument('--key', default=None,
                        help='explicit path to service keypair (PEM); overrides --name')
    args = parser.parse_args()

    _priv, _pub, resolved_key, _created = load_or_create_site_key(
        name=args.name, key=args.key,
    )

    host_str, port_str = args.target.rsplit(':', 1)
    host = HiddenServiceHost(host_str, int(port_str), resolved_key)
    print(f"[hs] key  = {resolved_key}")
    print(f"[hs] address = {host.address}")
    host.run()


if __name__ == '__main__':
    main()
