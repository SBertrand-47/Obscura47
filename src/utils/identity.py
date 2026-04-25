"""Process-local map of authenticated callers for ``.obscura`` services.

The hidden-service host already learns the dialing client's public key
during the rendezvous handshake (it's how end-to-end sealing of session
data is keyed). That knowledge is normally locked inside the host. This
module surfaces it to the application layer.

How it works
------------
Each rendezvous session corresponds to exactly one TCP connection from
the host process to the local application. The host registers
``(local_host, local_src_port) -> client_pub`` *before* it forwards any
bytes onto the local socket. The application's HTTP handler later
reads its accepted socket's ``client_address`` — which is the same
``(host, port)`` tuple — and can resolve the caller without changing
the wire format or peeking at the byte stream.

The registry is process-global on purpose: the lookup happens in code
paths (``BaseHTTPRequestHandler``) that don't have a clean way to be
parameterised. Keys are bounded by the number of in-flight sessions
and are cleaned up when the local socket closes, so the table stays
small.

Identity surfaces
-----------------
* ``caller_pub`` is the full PEM-encoded public key — useful for
  signature verification later.
* ``caller_fingerprint`` is a SHA-256 hex digest of the PEM bytes —
  short, comparable, suitable as a stable user id for a ledger or log.
"""

from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from typing import Iterator


_lock = threading.Lock()
_callers: dict[tuple[str, int], str] = {}


def _normalise(addr: tuple[str, int]) -> tuple[str, int]:
    host, port = addr[0], int(addr[1])
    if host == "::1":
        host = "127.0.0.1"
    return host, port


def register_caller(local_addr: tuple[str, int], pub_pem: str) -> None:
    """Associate a public key with a local TCP endpoint."""
    if not pub_pem:
        return
    key = _normalise(local_addr)
    with _lock:
        _callers[key] = pub_pem


def unregister_caller(local_addr: tuple[str, int]) -> None:
    """Remove the mapping for a local TCP endpoint, if any."""
    key = _normalise(local_addr)
    with _lock:
        _callers.pop(key, None)


def lookup_caller(local_addr: tuple[str, int] | None) -> str | None:
    """Return the registered ``caller_pub`` for a local endpoint, if any."""
    if not local_addr:
        return None
    key = _normalise(local_addr)
    with _lock:
        return _callers.get(key)


def clear_callers() -> None:
    """Drop every registration. Test helper; not for production paths."""
    with _lock:
        _callers.clear()


@contextmanager
def caller_session(local_addr: tuple[str, int], pub_pem: str) -> Iterator[None]:
    """Scope a registration to a ``with`` block.

    Convenience for callers that want guaranteed cleanup even if an
    exception is raised between registration and the natural unregister
    path.
    """
    register_caller(local_addr, pub_pem)
    try:
        yield
    finally:
        unregister_caller(local_addr)


def fingerprint_pubkey(pub_pem: str | None) -> str | None:
    """SHA-256 hex digest of a PEM public key, or ``None`` for missing input.

    Stable across processes — two different agents seeing the same
    caller pub get the same fingerprint, which makes it usable as a
    primary key for ledgers, audit logs, etc.
    """
    if not pub_pem:
        return None
    return hashlib.sha256(pub_pem.encode("utf-8")).hexdigest()
