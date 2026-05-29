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

import errno
import os
import threading
import time
from typing import Iterable

# Import config for its side effect: _load_dotenv() runs at config import time,
# which guarantees OBSCURA_* values from a project-root .env file are visible
# to our os.environ reads below even when peer_health is imported in isolation
# (e.g. from a test or a CLI tool that skips the node/exit entry points).
from src.utils import config as _config  # noqa: F401
from src.utils import diag
from src.utils.logger import get_logger

log = get_logger(__name__)


FAILURE_THRESHOLD = 2          # consecutive failures before peer is marked bad
COOLDOWN_SECONDS = 120.0       # how long a bad peer stays excluded
FAILURE_WINDOW_SECONDS = 60.0  # failures older than this don't count


# OS error codes that indicate the local machine has no IP route to the
# remote host - distinct from "peer refused / timed out", which would be
# the peer's fault. ENETUNREACH usually means an IPv6 peer was advertised
# to an IPv4-only host (or vice versa) or there's a routing outage on the
# local side. Either way, the peer isn't broken globally - only from this
# vantage point - so marking it locally is the right response.
_UNREACHABLE_NETWORK_CODES: set[int] = set()
for _name in ("ENETUNREACH", "EHOSTUNREACH"):
    _code = getattr(errno, _name, None)
    if isinstance(_code, int):
        _UNREACHABLE_NETWORK_CODES.add(_code)
# Windows surfaces these as WSA codes (10051/10065) on the WSA path and as
# raw Win32 ERROR_NETWORK_UNREACHABLE (1231) / ERROR_HOST_UNREACHABLE (1232)
# when a native connect() fails before sockets even get involved.
_UNREACHABLE_NETWORK_CODES.update({10051, 10065, 1231, 1232})


def is_unreachable_network_error(exc: BaseException | None) -> bool:
    """True if ``exc`` indicates the local host has no route to the remote.

    Inspects both ``winerror`` (set on Windows OSError for WSA / Win32
    codes) and ``errno`` (set on POSIX). Returns False for any other
    OSError so we don't conflate "I can't reach you" (local fact) with
    "you refused me" (peer fact).
    """
    if exc is None:
        return False
    win = getattr(exc, "winerror", None)
    if isinstance(win, int) and win in _UNREACHABLE_NETWORK_CODES:
        return True
    err = getattr(exc, "errno", None)
    return isinstance(err, int) and err in _UNREACHABLE_NETWORK_CODES


_lock = threading.Lock()
_state: dict[tuple[str, int], dict] = {}


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
    immediately eligible for selection again.
    """
    key = _key(host, port)
    if key is None:
        return
    with _lock:
        entry = _state.get(key)
        if entry and entry.get("fails"):
            log.info("peer_health: %s:%s recovered", host, port)
            diag.emit("peer_recovered", peer=f"{host}:{port}",
                      prior_fails=entry.get("fails"))
        _state[key] = {
            "fails": 0,
            "last_fail": 0.0,
            "cooldown_until": 0.0,
        }


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
            was_already_cool = entry.get("cooldown_until", 0.0) > now
            entry["cooldown_until"] = now + COOLDOWN_SECONDS
            log.warning(
                "peer_health: %s:%s marked unreachable (%d failures, reason=%s); "
                "excluded from circuits for %ds",
                host, port, entry["fails"], reason or "timeout", int(COOLDOWN_SECONDS),
            )
            if not was_already_cool:
                diag.emit(
                    "peer_cooled",
                    peer=f"{host}:{port}",
                    fails=entry["fails"],
                    reason=reason or "timeout",
                    cooldown_s=int(COOLDOWN_SECONDS),
                )
        _state[key] = entry


def mark_host_unreachable(peer: dict | None, reason: str = "") -> None:
    """Mark every known port of ``peer`` as failed at threshold.

    Used when an ENETUNREACH-class error surfaces - the local machine has
    no route to the host at all, so any port on that host is also
    unreachable from here. Records ``FAILURE_THRESHOLD`` failures at once
    so the peer flips straight to cooldown instead of after another live
    attempt eats another timeout. Local-only state: doesn't affect what
    other peers think of this host.
    """
    if not isinstance(peer, dict):
        return
    host = peer.get("host")
    if not host:
        return
    seen: set[int] = set()
    for key in ("port", "ws_port"):
        val = peer.get(key)
        try:
            port = int(val) if val else None
        except (TypeError, ValueError):
            continue
        if not port or port in seen:
            continue
        seen.add(port)
        for _ in range(FAILURE_THRESHOLD):
            mark_failure(host, port, reason=reason or "network unreachable")


def is_healthy(host: str | None, port: int | None) -> bool:
    """True if ``(host, port)`` is eligible for selection right now."""
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
    """True if ``peer``'s WS endpoint is healthy (or it has no WS endpoint).

    Peers without a ``ws_port`` are treated as healthy here because the
    WS transport - which is what silently times out - is bypassed for
    them; any TCP failure surfaces synchronously to the caller.
    """
    if not isinstance(peer, dict):
        return True
    ws_port = peer.get("ws_port")
    if not ws_port:
        return True
    return is_healthy(peer.get("host"), ws_port)


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


# ---------------------------------------------------------------------------
# Self-test: confirm our own WS port is reachable on the address we advertise
# ---------------------------------------------------------------------------

# Per-role outcome of the self-probe. ``ok`` is ``None`` until the first probe
# completes (so callers gated on a known-good probe can stay conservative at
# startup). ``consecutive_failures`` mirrors the (host, port) failure counter
# above and uses the same FAILURE_THRESHOLD to decide when to flip ``ok``.
_self_probe_lock = threading.Lock()
_self_probe: dict[str, dict] = {}


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def should_advertise_ws(role: str) -> bool:
    """Whether the heartbeat should include ``ws_port`` for ``role`` right now.

    Default (env var unset): always True - preserves prior behavior where the
    self-probe is purely diagnostic.

    With ``OBSCURA_REQUIRE_WS_REACHABLE=1``: only advertise once the self-probe
    has confirmed our WS port is reachable from the outside. A node behind a
    firewall / CGNAT then never tells the registry it speaks WS, so circuit
    builders never pick it for the WS hop and don't eat the dial timeout.
    """
    if not _env_truthy("OBSCURA_REQUIRE_WS_REACHABLE"):
        return True
    with _self_probe_lock:
        entry = _self_probe.get(role)
        if not entry or entry.get("ok") is None:
            # Never probed - stay conservative until we have a verdict.
            return False
        return bool(entry["ok"])


def _record_self_probe(role: str, ok: bool) -> bool:
    """Update the per-role probe state. Returns True iff ``ok`` changed."""
    with _self_probe_lock:
        entry = _self_probe.get(role) or {
            "ok": None, "consecutive_failures": 0, "last_check": 0.0,
        }
        prior_ok = entry.get("ok")
        entry["last_check"] = time.time()
        if ok:
            entry["consecutive_failures"] = 0
            entry["ok"] = True
        else:
            entry["consecutive_failures"] = int(entry.get("consecutive_failures", 0)) + 1
            # Mirror the FAILURE_THRESHOLD policy used for peer health: a single
            # transient failure doesn't flip the verdict, but a second one does.
            if entry["consecutive_failures"] >= FAILURE_THRESHOLD:
                entry["ok"] = False
            elif entry["ok"] is None:
                # First probe ever and it failed - leave verdict unknown so
                # callers without a strict requirement still get to advertise,
                # while strict callers (REQUIRE_WS_REACHABLE) stay suppressed.
                entry["ok"] = None
        _self_probe[role] = entry
        return prior_ok != entry["ok"]


def self_probe_snapshot() -> dict[str, dict]:
    """Copy of the per-role self-probe state. For diagnostics/tests."""
    with _self_probe_lock:
        return {k: dict(v) for k, v in _self_probe.items()}


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


def _registry_ws_masked(role: str, host: str, ws_port: int) -> bool | None:
    """Authoritative external verdict on our ws_port reachability.

    The registry probes every advertised ws_port from its own vantage and
    *masks* it out of ``/peers`` when the probe fails - so if our own entry
    still carries ``ws_port``, the wider network can dial us; if it has been
    masked, it cannot. This is a true "reachable from obscura" signal because
    the registry dials us from outside our host (unlike a local self-connect,
    which a cloud security group can let through while still blocking peers).

    Returns ``True`` if masked (unreachable), ``False`` if still advertised
    (reachable), or ``None`` when the registry can't be consulted / doesn't
    list us yet.
    """
    try:
        from src.core import internet_discovery
        peers = internet_discovery.fetch_peers_from_registry(role_filter=role) or []
        candidate_hosts = {h for h in (host, internet_discovery._my_public_ip) if h}
    except Exception as e:
        log.debug("self-probe: registry verdict unavailable: %s", e)
        return None
    mine = [p for p in peers
            if p.get("role") == role and p.get("host") in candidate_hosts]
    if not mine:
        return None
    for p in mine:
        try:
            if p.get("ws_port") is not None and int(p["ws_port"]) == int(ws_port):
                return False  # still advertised -> reachable
        except (TypeError, ValueError):
            continue
    return True  # we appear, but ws_port has been masked everywhere -> unreachable


def _firewall_open_plan(port: int) -> tuple[str | None, list[str] | None]:
    """Best-effort (human-readable command, argv) to allow inbound TCP on
    ``port`` for the detected platform firewall, or ``(None, None)``."""
    import platform
    import shutil
    if platform.system().lower().startswith("win"):
        argv = ["netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Obscura47 {port}", "dir=in", "action=allow",
                "protocol=TCP", f"localport={port}"]
        return " ".join(argv), argv
    if shutil.which("ufw"):
        return f"sudo ufw allow {port}/tcp", ["ufw", "allow", f"{port}/tcp"]
    if shutil.which("firewall-cmd"):
        return (f"sudo firewall-cmd --add-port={port}/tcp  (add --permanent to persist)",
                ["firewall-cmd", f"--add-port={port}/tcp"])
    if shutil.which("iptables"):
        return (f"sudo iptables -I INPUT -p tcp --dport {port} -j ACCEPT",
                ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
    return None, None


def _auto_open_enabled() -> bool:
    """``OBSCURA_AUTO_OPEN_PORTS=1`` lets the node open its own port.

    This is the operator's consent: you own the box, so with the flag set we
    run the firewall command for you instead of only printing it.
    """
    return os.environ.get("OBSCURA_AUTO_OPEN_PORTS", "").strip().lower() in (
        "1", "true", "yes", "on")


def _try_open_firewall(port: int) -> tuple[bool, str]:
    """Attempt to open inbound TCP on ``port`` via the platform firewall.

    Non-interactive by design (``sudo -n``): if it needs privileges we don't
    have, it fails fast and the caller logs the manual command rather than
    hanging a background thread on a password prompt.
    """
    import shutil
    import subprocess
    desc, argv = _firewall_open_plan(port)
    if not argv:
        return False, "no supported firewall tool found (ufw/firewall-cmd/iptables/netsh)"
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        if shutil.which("sudo"):
            argv = ["sudo", "-n", *argv]
        else:
            return False, f"need root to run `{desc}` and sudo is unavailable"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True, f"ran `{desc}`"
        return False, f"`{desc}` failed ({r.returncode}): {(r.stderr or r.stdout).strip()[:200]}"
    except Exception as e:
        return False, f"could not run `{desc}`: {e}"


def diagnose_ws_reachability(role: str, host: str, ws_port: int,
                              timeout: float = 3.0) -> dict:
    """Decide whether our ``ws_port`` is reachable and explain why.

    Prefers the registry's external verdict (authoritative "reachable from
    obscura"); falls back to a local self-connect when the registry can't be
    consulted. Always includes a concrete fix command when one is available.
    """
    masked = _registry_ws_masked(role, host, ws_port)
    if masked is True:
        reachable, source = False, "registry"
        detail = "the registry probed your ws_port from the public internet and could not reach it"
    elif masked is False:
        reachable, source = True, "registry"
        detail = "the registry can reach your ws_port from the public internet"
    else:
        reachable, why = probe_tcp(host, ws_port, timeout=timeout)
        source = "local"
        detail = ("local self-connect to your advertised address succeeded"
                  if reachable else f"local self-connect failed ({why})")
    desc, _argv = _firewall_open_plan(ws_port)
    return {
        "reachable": reachable, "source": source, "detail": detail,
        "role": role, "host": host, "ws_port": ws_port, "fix_command": desc,
    }


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
                time.sleep(min(interval, 30.0))
                continue

            verdict = diagnose_ws_reachability(role, host, ws_port)
            ok = verdict["reachable"]

            # With the operator's consent, try to open the port ourselves
            # before giving up - then re-check so a successful open flips us
            # back to healthy immediately.
            opened_note = ""
            if not ok and _auto_open_enabled():
                done, msg = _try_open_firewall(ws_port)
                opened_note = f" | auto-open: {msg}"
                if done:
                    time.sleep(1.0)
                    verdict = diagnose_ws_reachability(role, host, ws_port)
                    ok = verdict["reachable"]

            changed = _record_self_probe(role, ok)
            if ok:
                log.info(
                    "peer_health self-probe (%s): %s:%s reachable via %s - %s%s%s",
                    role, host, ws_port, verdict["source"], verdict["detail"],
                    opened_note, " (recovered)" if changed else "",
                )
            else:
                fix = verdict.get("fix_command")
                if opened_note:
                    next_step = opened_note
                elif fix:
                    next_step = (f" Fix: open inbound TCP on {ws_port}, e.g. `{fix}` "
                                 f"(or set OBSCURA_AUTO_OPEN_PORTS=1 to let Obscura47 run it).")
                else:
                    next_step = (f" Fix: allow inbound TCP on {ws_port} in your firewall, "
                                 f"cloud security group, or NAT port-forward.")
                log.error(
                    "peer_health self-probe (%s): %s:%s UNREACHABLE (%s) - %s. "
                    "Peers cannot build circuits through this node, so traffic "
                    "to the clearnet and .obscura sites fails.%s",
                    role, host, ws_port, verdict["source"], verdict["detail"],
                    next_step,
                )
            time.sleep(interval)

    t = threading.Thread(target=_loop, name=f"ws-self-probe-{role}", daemon=True)
    t.start()
    return t
