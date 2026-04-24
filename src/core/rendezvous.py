"""Client-side dial of an Obscura hidden service.

The proxy calls :func:`dial_hidden_service` when it sees a CONNECT to a
`.obscura` host. The function fetches the descriptor from the registry,
picks a meeting point, sends an `hs_connect` along an onion route, and
returns the (route, request_id) pair. From there the proxy reuses its
existing tunnel-pumping machinery — `hs_data` and `hs_close` frames piggy-
back on the same reverse-channel pipe as ordinary exit tunnels.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Any

from src.core.router import send_hs_frame
from src.utils.config import REGISTRY_URL
from src.utils.logger import get_logger
from src.utils.onion_addr import verify_descriptor

log = get_logger(__name__)


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


def dial_hidden_service(addr: str, proxy_pub_pem: str) -> tuple[list[dict], str, str] | None:
    """Open an HS session; returns (route, request_id, service_pub) for the proxy to drive."""
    desc = fetch_descriptor(addr)
    if not desc:
        return None
    intros = desc.get('intro_points') or []
    if not intros:
        log.warning("Descriptor for %s has no intro points", addr)
        return None

    # v1: single meeting point — use the first one the descriptor advertises.
    mp = intros[0]
    route = [mp]
    request_id = f"C{time.time_ns()}"
    service_pub = desc.get('pubkey') or ''

    envelope = {
        'type': 'hs_connect',
        'request_id': request_id,
        'service_addr': addr,
        'pub': proxy_pub_pem,
    }
    if not send_hs_frame(route, envelope):
        log.warning("hs_connect send failed for %s", addr)
        return None
    return route, request_id, service_pub


def send_hs_chunk(route: list[dict], request_id: str, sealed_chunk: str) -> bool:
    """Send an hs_data frame. ``sealed_chunk`` is the service-pub-sealed
    payload string; the meeting point treats it as opaque."""
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
