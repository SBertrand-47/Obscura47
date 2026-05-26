"""In-process peer health tracker.

Records WS-transport successes/failures per ``(host, ws_port)`` so circuit
builders can skip peers that recently proved unreachable. Without this,
a relay whose WS port is firewalled or whose process is wedged stays in
the route-selection pool indefinitely and every circuit that picks it
burns ~15s on a handshake timeout.

The tracker has three states for a peer:

* **healthy** - no recent failure, or last failure was a one-off followed
  by a success.
* **cooling-down** - two or more consecutive failures within the failure
  window; excluded from selection for ``COOLDOWN_SECONDS``.
* **probation** - cooldown expired; one attempt allowed. On success the
  peer is healthy again; on failure the cooldown re-extends.

Health is keyed by ``(host, ws_port)`` because that is the tuple the WS
transport actually dials. TCP-only peers (no ``ws_port``) are always
treated as healthy by ``is_peer_healthy`` - the WS path is what fails
silently; TCP failures surface immediately to the caller.
"""

from __future__ import annotations

import threading
import time
from typing import Iterable

from src.utils.logger import get_logger

log = get_logger(__name__)


FAILURE_THRESHOLD = 2          # consecutive failures before peer is marked bad
COOLDOWN_SECONDS = 120.0       # how long a bad peer stays excluded
FAILURE_WINDOW_SECONDS = 60.0  # failures older than this don't count


_lock = threading.Lock()
_state: dict[tuple[str, int], dict] = {}

# Host-level cooldown. When any port on a host crosses the failure
# threshold the host gets marked unhealthy for COOLDOWN_SECONDS so that
# every peer entry sharing the host is excluded - even TCP-only entries
# that don't carry a ws_port and would otherwise bypass the port-keyed
# filter. Same machine, same unreachability.
_host_cooldown: dict[str, float] = {}


def _key(host: str | None, port: int | None) -> tuple[str, int] | None:
    if not host or not port:
        return None
    try:
        return (str(host), int(port))
    except (TypeError, ValueError):
        return None


def mark_success(host: str, port: int) -> None:
    """Record a successful WS send to ``(host, port)``.

    Clears any prior failure state so a peer that comes back online is
    immediately eligible for selection again. Also clears the
    host-level cooldown - a working port is strong evidence the host
    itself is reachable.
    """
    key = _key(host, port)
    if key is None:
        return
    with _lock:
        entry = _state.get(key)
        if entry and entry.get("fails"):
            log.info("peer_health: %s:%s recovered", host, port)
        _state[key] = {
            "fails": 0,
            "last_fail": 0.0,
            "cooldown_until": 0.0,
        }
        _host_cooldown.pop(str(host), None)


def mark_failure(host: str, port: int, reason: str = "") -> None:
    """Record a failed WS send/connect to ``(host, port)``.

    Increments the failure counter. Once ``FAILURE_THRESHOLD`` consecutive
    failures land inside ``FAILURE_WINDOW_SECONDS`` the peer enters a
    cooldown and is excluded from route selection.
    """
    key = _key(host, port)
    if key is None:
        return
    now = time.time()
    with _lock:
        entry = _state.get(key) or {"fails": 0, "last_fail": 0.0, "cooldown_until": 0.0}
        # Reset the counter if the prior failure is older than the window -
        # we only care about *recent* repeated failure, not lifetime totals.
        if entry["fails"] and (now - entry["last_fail"]) > FAILURE_WINDOW_SECONDS:
            entry["fails"] = 0
        entry["fails"] += 1
        entry["last_fail"] = now
        if entry["fails"] >= FAILURE_THRESHOLD:
            entry["cooldown_until"] = now + COOLDOWN_SECONDS
            _host_cooldown[str(host)] = now + COOLDOWN_SECONDS
            log.warning(
                "peer_health: %s:%s marked unreachable (%d failures, reason=%s); "
                "excluded from circuits for %ds",
                host, port, entry["fails"], reason or "timeout", int(COOLDOWN_SECONDS),
            )
        _state[key] = entry


def _host_in_cooldown(host: str | None) -> bool:
    """True if the host itself is in a global cooldown (any-port failure)."""
    if not host:
        return False
    with _lock:
        until = _host_cooldown.get(str(host), 0.0)
    return bool(until and time.time() < until)


def is_healthy(host: str | None, port: int | None) -> bool:
    """True if ``(host, port)`` is eligible for selection right now.

    Returns False if either the specific port is in cooldown *or* the
    host as a whole is in cooldown - one dead port on a host is strong
    evidence other ports on the same host are unreachable too (same
    machine, same firewall, same NAT).
    """
    if _host_in_cooldown(host):
        return False
    key = _key(host, port)
    if key is None:
        return True
    with _lock:
        entry = _state.get(key)
        if not entry:
            return True
        if entry["cooldown_until"] and time.time() < entry["cooldown_until"]:
            return False
        return True


def is_peer_healthy(peer: dict | None) -> bool:
    """True if ``peer``'s host is reachable.

    Checks the host-level cooldown first so a LAN peer that advertises
    no ``ws_port`` (and would otherwise sneak past the port-keyed
    filter) still gets excluded when its host is known-bad. Falls back
    to the WS port check when available.
    """
    if not isinstance(peer, dict):
        return True
    host = peer.get("host")
    if _host_in_cooldown(host):
        return False
    ws_port = peer.get("ws_port")
    if not ws_port:
        return True
    return is_healthy(host, ws_port)


def filter_healthy(peers: Iterable[dict]) -> list[dict]:
    """Return only the peers currently considered healthy.

    Callers should fall back to the unfiltered pool when this returns an
    empty list - an outage that takes down every relay should still let
    the next attempt try (and re-mark) something.
    """
    return [p for p in peers if is_peer_healthy(p)]


def snapshot() -> dict[tuple[str, int], dict]:
    """Return a copy of the current health state. For diagnostics/tests."""
    with _lock:
        return {k: dict(v) for k, v in _state.items()}


def reset() -> None:
    """Clear all tracked health state. For tests."""
    with _lock:
        _state.clear()
        _host_cooldown.clear()


# ---------------------------------------------------------------------------
# Self-test: confirm our own WS port is reachable on the address we advertise
# ---------------------------------------------------------------------------

def probe_tcp(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Best-effort TCP reachability probe. Returns ``(ok, detail)``."""
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, ""
    except socket.timeout:
        return False, "timed out"
    except OSError as e:
        return False, str(e) or e.__class__.__name__
    except Exception as e:
        return False, f"{e.__class__.__name__}: {e}"


def start_self_ws_probe(
    role: str,
    ws_port: int,
    *,
    advertised_host: str | None = None,
    initial_delay: float = 8.0,
    interval: float = 300.0,
) -> "threading.Thread":
    """Periodically probe our own advertised ``ws_port`` from the outside.

    A node whose WS port is firewalled silently poisons every circuit that
    picks it - the registry still says it's alive because HTTP heartbeats
    work, but every WS handshake against it times out. This probe catches
    that case server-side and prints a loud, actionable error.

    The probe targets ``advertised_host`` when set, otherwise the public
    IP the registry assigned us at first heartbeat (``_my_public_ip``).
    Falls back to noop with a debug log if neither is known yet.
    """
    def _loop():
        # Let the WSServer finish binding and let the first heartbeat land
        # so we know our public IP.
        time.sleep(initial_delay)
        from src.core import internet_discovery
        while True:
            host = advertised_host or internet_discovery._my_public_ip
            if not host:
                log.debug("peer_health self-probe (%s): no advertised host yet, skipping", role)
            else:
                ok, why = probe_tcp(host, ws_port, timeout=3.0)
                if ok:
                    log.info(
                        "peer_health self-probe (%s): %s:%s reachable - ws_port is "
                        "accepting external connections",
                        role, host, ws_port,
                    )
                else:
                    log.error(
                        "peer_health self-probe (%s): %s:%s UNREACHABLE (%s). "
                        "Other peers will time out building circuits through "
                        "this node. Likely causes: (1) firewall blocking "
                        "inbound TCP on %s, (2) NAT without port forward, "
                        "(3) WSServer never bound. Open the port or stop "
                        "advertising ws_port to keep the network healthy.",
                        role, host, ws_port, why, ws_port,
                    )
            time.sleep(interval)

    t = threading.Thread(target=_loop, name=f"ws-self-probe-{role}", daemon=True)
    t.start()
    return t
