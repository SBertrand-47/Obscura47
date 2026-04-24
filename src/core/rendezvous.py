"""Client-side dial of an Obscura hidden service.

The proxy calls :func:`dial_hidden_service` when it sees a CONNECT to a
`.obscura` host. The function:

1. Fetches and verifies the descriptor from the registry.
2. Picks an intro point from the descriptor and a distinct rendezvous
   relay from the general peer pool.
3. Opens an rv_establish circuit to the rendezvous point with a random
   cookie.
4. Opens an hs_introduce circuit to the intro point, sealing
   (rv_point, cookie, client_pub) to the service pubkey so the intro
   point can't read it.
5. Waits for the rendezvous point to report `rv_ready` (meaning the host
   joined on the cookie and the circuits are spliced).
6. Returns the rv_route and rv_request_id, which the proxy uses to pump
   hs_data frames. Chunks are sealed end-to-end with the service pubkey.
"""

from __future__ import annotations

import base64
import json
import os
import random
import threading
import time
import urllib.request
from typing import Any

from src.core.encryptions import onion_encrypt_for_peer
from src.core.internet_discovery import fetch_peers_from_registry
from src.core.router import send_hs_frame
from src.utils.config import REGISTRY_URL
from src.utils.logger import get_logger
from src.utils.onion_addr import verify_descriptor

log = get_logger(__name__)


# Track per-rv-circuit rv_ready events so the proxy's reverse-frame
# dispatcher can signal us when the rendezvous point acknowledges the
# splice. Keyed by client rv request_id.
_ready_events: dict[str, threading.Event] = {}
_ready_lock = threading.Lock()


def register_ready_event(request_id: str, event: threading.Event) -> None:
    with _ready_lock:
        _ready_events[request_id] = event


def pop_ready_event(request_id: str) -> threading.Event | None:
    with _ready_lock:
        return _ready_events.pop(request_id, None)


def notify_rv_ready(request_id: str) -> None:
    """Proxy calls this when an `rv_ready` inner frame arrives."""
    with _ready_lock:
        ev = _ready_events.get(request_id)
    if ev:
        ev.set()


def fetch_descriptor(addr: str) -> dict[str, Any] | None:
    url = f"{REGISTRY_URL}/hs/descriptor/{addr}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            desc = json.loads(resp.read())
    except Exception as e:
        log.warning("Descriptor fetch failed for %s: %s", addr, e)
        return None
    if not verify_descriptor(desc):
        log.warning("Descriptor verification failed for %s", addr)
        return None
    return desc


def _pick_rendezvous_point(
    peers: list[dict],
    exclude: set[tuple[str, int]],
) -> dict | None:
    # Accept any peer with host/port/pub. relay_peers by convention holds
    # node relays; registry-sourced peers also carry role='node'.
    candidates = [
        p for p in peers
        if p.get('pub') and p.get('host') and p.get('port')
        and (p.get('role') in (None, 'node'))
        and (p.get('host'), p.get('port')) not in exclude
    ]
    if not candidates:
        return None
    return random.choice(candidates)


def dial_hidden_service(
    addr: str,
    proxy_pub_pem: str,
    peers: list[dict] | None = None,
    ready_timeout: float = 10.0,
) -> tuple[list[dict], str, str] | None:
    """Open an HS session via separate intro + rendezvous relays.

    Returns (rv_route, rv_request_id, service_pub) on success. Chunks
    sent via `send_hs_chunk` on rv_route travel to the host through the
    rendezvous point. Returns None if any step fails.
    """
    desc = fetch_descriptor(addr)
    if not desc:
        return None
    intros = desc.get('intro_points') or []
    if not intros:
        log.warning("Descriptor for %s has no intro points", addr)
        return None
    service_pub = desc.get('pubkey') or ''
    if not service_pub:
        log.warning("Descriptor for %s missing pubkey", addr)
        return None

    intro_point = random.choice(intros)

    if peers is None:
        peers = fetch_peers_from_registry() or []
    rv_point = _pick_rendezvous_point(
        peers,
        exclude={(intro_point.get('host'), intro_point.get('port'))},
    )
    if not rv_point:
        # Fall back to any node in the intro list that isn't the picked
        # intro — small networks may not offer a separate relay.
        fallback = [p for p in intros if p is not intro_point]
        if fallback:
            rv_point = random.choice(fallback)
        else:
            log.warning("No rendezvous point available distinct from intro")
            return None

    # 1. Rendezvous circuit: establish with a cookie.
    cookie = base64.b64encode(os.urandom(16)).decode()
    rv_req_id = f"C{time.time_ns()}"
    rv_route = [rv_point]
    ready = threading.Event()
    register_ready_event(rv_req_id, ready)

    rv_env = {
        'type': 'rv_establish',
        'request_id': rv_req_id,
        'cookie': cookie,
        'pub': proxy_pub_pem,
    }
    if not send_hs_frame(rv_route, rv_env):
        pop_ready_event(rv_req_id)
        log.warning("rv_establish send failed for %s", addr)
        return None

    # 2. Intro circuit: sealed introduce payload containing rv info + cookie.
    payload = json.dumps({
        'rv_point': {
            'host': rv_point.get('host'),
            'port': rv_point.get('port'),
            'ws_port': rv_point.get('ws_port'),
            'pub': rv_point.get('pub'),
        },
        'cookie': cookie,
        'client_pub': proxy_pub_pem,
    })
    sealed_introduce = onion_encrypt_for_peer(service_pub, payload)

    intro_req_id = f"I{time.time_ns()}"
    intro_env = {
        'type': 'hs_introduce',
        'request_id': intro_req_id,
        'service_addr': addr,
        'introduce_payload': sealed_introduce,
    }
    if not send_hs_frame([intro_point], intro_env):
        pop_ready_event(rv_req_id)
        log.warning("hs_introduce send failed for %s", addr)
        return None

    # 3. Wait for the rv point to confirm the host joined.
    if not ready.wait(timeout=ready_timeout):
        pop_ready_event(rv_req_id)
        log.warning("rv_ready timeout for %s", addr)
        return None
    pop_ready_event(rv_req_id)

    return rv_route, rv_req_id, service_pub


def send_hs_chunk(route: list[dict], request_id: str, sealed_chunk: str) -> bool:
    """Send an hs_data frame along the rendezvous circuit. ``sealed_chunk``
    is already encrypted to the service pubkey — the rendezvous point
    only relays ciphertext."""
    envelope = {
        'type': 'hs_data',
        'request_id': request_id,
        'chunk': sealed_chunk,
    }
    return bool(send_hs_frame(route, envelope))


def close_hs(route: list[dict], request_id: str) -> None:
    send_hs_frame(route, {
        'type': 'hs_close',
        'request_id': request_id,
    })
