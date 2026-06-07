"""
Internet-based peer discovery via the Obscura47 bootstrap registry.

Nodes call `register_with_registry()` on startup and periodically to heartbeat.
Proxies call `fetch_peers_from_registry()` to get internet-wide peers.

Supports ECDSA challenge-response auth when a node provides its ECC private key.
"""

import atexit
import ipaddress
import json
import os
import socket
import ssl
import time
import threading
import urllib.error
import urllib.request
from typing import List, Dict, Callable
from src.core.discover import _merge_peer
from src.utils.config import (
    REGISTRY_URL, REGISTRY_HEARTBEAT_INTERVAL, PEER_EXPIRY_SECONDS,
    TLS_VERIFY, ADMIN_PUB_PEM, KILL_SWITCH_CHECK_INTERVAL,
    NODE_LISTEN_PORT, EXIT_LISTEN_PORT, NODE_WS_PORT, EXIT_WS_PORT,
    NODE_ADVERTISED_HOST, EXIT_ADVERTISED_HOST,
    NODE_KEY_PATH, EXIT_KEY_PATH,
)
from src.utils import diag
from src.utils.logger import get_logger

log = get_logger(__name__)

# Public IP as seen by the registry - set on first successful registration.
# Used to filter self out of the peer lists returned by the registry.
_my_public_ip: str | None = None

# Per-role heartbeat state. ``peer_id`` and ``priv_key`` let us send a signed
# deregister at shutdown so the registry purges us immediately instead of
# waiting out PEER_TTL (~120s). Without this hook other peers would keep
# routing through us for up to two minutes after the user clicks Disconnect.
_heartbeat_state: dict[str, dict] = {}
_heartbeat_lock = threading.Lock()
_atexit_registered = False

# Cache of local node/exit pubkeys (computed once from the local key files).
# Lets a host process colocated with a node identify "self" peers by pubkey
# even when host:port matching is ambiguous.
_self_pubs_cache: set[str] | None = None

# Per-role registration classification. ``_role_kind[role]`` is ``"primary"``
# when this node owns the public-IP slot for its NAT, ``"sibling"`` when
# another node behind the same NAT got there first and we registered under
# our LAN address instead. ``_primary_peer`` is the gateway peer (the
# primary's host/port/pub) that siblings route through; ``None`` when we
# are the primary or no primary is registered yet.
_role_kind: dict[str, str] = {}
_primary_peer: dict | None = None
# Cached effective advertised_host per role. Once 409→LAN fallback succeeds
# we keep registering under the LAN address so subsequent heartbeats don't
# repeatedly trip the public-slot conflict.
_effective_advertised_host: dict[str, str] = {}
_registration_state_lock = threading.Lock()

# Gateway forward brokering. The node (which owns the GatewayForwarder and the
# WS transport) registers a provisioner here; the heartbeat - which owns the
# /register round-trip - calls it with any pending_forwards the registry hands
# back and stashes the resulting grants as request fields for the next body.
# This keeps the node -> internet_discovery import direction intact.
_forward_provisioner = None  # callable(pending_forwards: list) -> granted: list
_forward_request_fields: dict = {}  # extra /register body fields (want_forward, granted_forwards)
_forward_lock = threading.Lock()


def set_forward_provisioner(fn) -> None:
    """Register the gateway's provisioner callback (called by the node)."""
    global _forward_provisioner
    with _forward_lock:
        _forward_provisioner = fn


def set_forward_request_fields(**fields) -> None:
    """Merge extra fields (want_forward / granted_forwards) into future /register bodies."""
    with _forward_lock:
        _forward_request_fields.update(fields)


def _consume_forward_request_fields() -> dict:
    with _forward_lock:
        return dict(_forward_request_fields)


def _run_forward_provisioner(pending_forwards: list) -> None:
    """Hand pending forwards to the gateway provisioner and report grants next heartbeat."""
    with _forward_lock:
        fn = _forward_provisioner
    if not fn or not pending_forwards:
        return
    try:
        granted = fn(pending_forwards)
    except Exception as e:
        log.warning("Forward provisioner failed: %s", e)
        return
    if granted:
        set_forward_request_fields(granted_forwards=granted)


def _pick_local_lan_ip() -> str | None:
    """Return a single private IPv4 suitable for use as advertised_host.

    Uses the same UDP-connect trick as ``_local_interface_ips`` but picks
    the address the OS would actually use to reach the public internet -
    i.e. the LAN IP bound to the default route interface. Returns ``None``
    if no private IPv4 is detected (host is on a public IP directly, or
    everything is loopback).
    """
    try:
        import ipaddress
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and ipaddress.ip_address(ip).is_private:
            return ip
    except Exception:
        pass
    # Fall back to scanning enumerated interface IPs for the first private v4.
    for ip in _local_interface_ips():
        try:
            import ipaddress
            parsed = ipaddress.ip_address(_strip_v6_zone(ip))
            if parsed.version == 4 and parsed.is_private and not parsed.is_loopback:
                return str(parsed)
        except Exception:
            continue
    return None


def get_role_kind(role: str = "node") -> str | None:
    """Return ``"primary"`` / ``"sibling"`` for *role*, or ``None`` if unknown.

    Unknown means: we haven't registered yet (or the registry response did
    not classify us). Callers that need to gate behavior on role kind
    should treat ``None`` the same as ``"primary"`` until a classified
    response arrives - matches the current "no special handling" default.
    """
    with _registration_state_lock:
        return _role_kind.get(role)


def get_primary_peer() -> dict | None:
    """Return the primary peer (gateway) this sibling registered behind.

    ``None`` when we are the primary, or when no primary is yet registered
    for this NAT. The dict shape matches a /peers entry: ``host``, ``port``,
    ``pub``, optionally ``ws_port`` / ``ws_tls``.
    """
    with _registration_state_lock:
        return dict(_primary_peer) if _primary_peer else None


def _normalize_pem(pem: str | None) -> str:
    """Strip whitespace differences so two equivalent PEMs compare equal."""
    if not pem:
        return ""
    return "".join(pem.split())


def _local_interface_ips() -> set[str]:
    """Best-effort enumeration of IPs bound to this machine.

    Combines four sources so a dual-stack box doesn't accidentally
    publish its own public IPv6 (or a privacy-extension temporary
    address that differs from the routable one) as an intro point:

    1. Hostname resolution (``gethostbyname_ex`` / ``getaddrinfo``).
    2. UDP-connect source-IP trick (works for both v4 and v6).
    3. Parsing ``ifconfig`` / ``ip -o addr`` output, which enumerates
       *every* address on every interface even when there's no route
       to an external probe target.
    4. ``OBSCURA_EXTRA_SELF_IPS`` env var (comma-separated explicit
       overrides for environments where automatic detection misses
       something).
    """
    ips: set[str] = {"127.0.0.1", "::1", "localhost"}
    try:
        hostname = socket.gethostname()
        try:
            _, _, addrs = socket.gethostbyname_ex(hostname)
            ips.update(a for a in addrs if a)
        except Exception:
            pass
        try:
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip:
                    ips.add(_strip_v6_zone(ip))
        except Exception:
            pass
    except Exception:
        pass

    # UDP-connect trick: ask the OS which source IP it would pick for
    # an outbound route to a public address. No packets are sent (UDP
    # connect just sets the default destination).
    for family, destination in (
        (socket.AF_INET, ("1.1.1.1", 80)),
        (socket.AF_INET6, ("2606:4700:4700::1111", 80)),
    ):
        try:
            s = socket.socket(family, socket.SOCK_DGRAM)
            try:
                s.connect(destination)
                ip = s.getsockname()[0]
                if ip:
                    ips.add(_strip_v6_zone(ip))
            finally:
                s.close()
        except Exception:
            pass

    # Shell out to ifconfig / ip to enumerate every interface address.
    # Works even when there's no outbound IPv6 route to the probe
    # target, and catches IPv6 privacy temporary addresses that the
    # UDP-connect trick misses (the OS may pick the temporary, while
    # the node-registration code published the stable one).
    ips.update(_enumerate_interface_ips_shell())

    # Explicit env-var override.
    extra = os.environ.get("OBSCURA_EXTRA_SELF_IPS", "").strip()
    if extra:
        for raw in extra.split(","):
            ip = raw.strip()
            if ip:
                ips.add(_strip_v6_zone(ip))
    return ips


def _strip_v6_zone(ip: str) -> str:
    """Drop the ``%en0``-style zone suffix from a link-local IPv6."""
    if "%" in ip:
        return ip.split("%", 1)[0]
    return ip


def _enumerate_interface_ips_shell() -> set[str]:
    """Parse ``ip -o addr`` or ``ifconfig`` output for interface IPs.

    Cross-platform stdlib-only fallback - the UDP-connect trick relies
    on an outbound route existing, but a host may have a publicly-
    routable IPv6 address bound to an interface with no default v6
    route (or with IPv6 firewalled outbound), in which case getsockname
    fails or returns a different address than what's actually bound.
    """
    import re
    import subprocess
    candidates: set[str] = set()
    for argv in (("ip", "-o", "addr"), ("ifconfig",)):
        try:
            out = subprocess.run(
                argv, capture_output=True, text=True, timeout=2,
            ).stdout
        except Exception:
            continue
        if not out:
            continue
        # ``ip -o addr``:    "2: en0    inet 192.168.1.105/24 ..."
        # ``ifconfig``:      "        inet 192.168.1.105 netmask 0xffffff00 ..."
        #                    "        inet6 fe80::1%en0 prefixlen 64 ..."
        for token in re.findall(
            r"\binet6?\s+([0-9a-fA-F:.]+)(?:[/%]|\s)", out,
        ):
            ip = _strip_v6_zone(token)
            if ip:
                candidates.add(ip)
        if candidates:
            return candidates
    return candidates


def get_self_peer_keys() -> set[tuple[str, int]]:
    """(host, port) tuples that identify peers running on this machine.

    Combines: the public IP learned from registry registration, any
    explicitly-configured advertised host, and local interface IPs - each
    paired with the local node/exit listen ports.
    """
    keys: set[tuple[str, int]] = set()
    hosts: set[str] = set()
    if _my_public_ip:
        hosts.add(_my_public_ip)
    if NODE_ADVERTISED_HOST:
        hosts.add(NODE_ADVERTISED_HOST)
    if EXIT_ADVERTISED_HOST:
        hosts.add(EXIT_ADVERTISED_HOST)
    hosts.update(_local_interface_ips())
    for h in hosts:
        keys.add((h, NODE_LISTEN_PORT))
        keys.add((h, EXIT_LISTEN_PORT))
    return keys


def get_self_peer_pubs() -> set[str]:
    """Normalized PEM strings of locally-running node/exit pubkeys.

    Read from the on-disk key files. Cached - changes to the files require
    a process restart to take effect.
    """
    global _self_pubs_cache
    if _self_pubs_cache is not None:
        return _self_pubs_cache
    pubs: set[str] = set()
    for path in (NODE_KEY_PATH, EXIT_KEY_PATH):
        try:
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    pem = f.read()
                from Crypto.PublicKey import ECC
                priv = ECC.import_key(pem)
                pub_pem = priv.public_key().export_key(format="PEM")
                pubs.add(_normalize_pem(pub_pem))
        except Exception:
            continue
    _self_pubs_cache = pubs
    return pubs


def is_public_internet_host(host: str | None) -> bool:
    """True if ``host`` looks routable across the public internet.

    A peer advertised on an RFC1918 / link-local / loopback address is
    only useful to clients on the same LAN. Picking such a peer as a
    rendezvous point silently breaks `.obscura` dials whenever the host
    sits on a different network - its rv_join never reaches the LAN-only
    relay and the splice never happens.
    """
    if not host:
        return False
    s = str(host).strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        # Hostnames are assumed public; DNS will resolve them at dial time.
        return True
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def is_self_peer(peer: dict | None) -> bool:
    """True if ``peer`` resolves to a node/exit running on this machine.

    Used to filter our own machine out of HS route construction, intro-point
    selection, and rendezvous-point selection - otherwise a circuit
    originating from this machine would try to NAT-loop back to itself.
    """
    if not peer:
        return False
    host = peer.get("host")
    port = peer.get("port")
    if host and port and (host, port) in get_self_peer_keys():
        return True
    pub = peer.get("pub")
    if pub and _normalize_pem(pub) in get_self_peer_pubs():
        return True
    # Last line of defence: any peer at our public IP, regardless of port
    # or pubkey, is on our network. When two LAN machines share a NAT the
    # registry's (host, port) primary key collapses them into one entry
    # whose pubkey may belong to the other machine - making the pubkey
    # check above silently fail. Routing through our own WAN IP is
    # never useful and tends to be unreachable anyway (no port forward).
    if host and _my_public_ip and host == _my_public_ip:
        # Exception for a same-NAT fleet (OBSCURA_ALLOW_LAN_PEERS): a
        # SIBLING - a different machine sharing our WAN IP, advertising its
        # own distinct service pubkey - is a real relay reachable over the
        # LAN, and is in fact the normal rendezvous/intro path here. We have
        # already returned True above if this peer matched our own
        # (host, port) or our own pubkey, so a peer that reaches this point
        # carrying a non-empty, distinct pubkey is a sibling, not us; keep it
        # usable instead of NAT-loop-filtering it. A pubkey-less collapsed
        # entry stays filtered (we cannot prove it is not us).
        if allow_lan_peers() and peer.get("pub"):
            return False
        return True
    return False


def learn_public_ip(force: bool = False) -> str | None:
    """Learn this machine's public IP from the registry.

    Calls the registry's /whoami endpoint and caches the result in
    ``_my_public_ip``. Useful for processes that don't otherwise
    register (e.g. a hidden-service host) but still need to recognise
    themselves in the peer list to avoid picking themselves as an
    intro or rendezvous point.

    Falls back to the ``OBSCURA_MY_PUBLIC_IP`` env var if the registry
    doesn't implement /whoami (old deployment) so users can hard-set
    the IP without redeploying anything.
    """
    global _my_public_ip
    if _my_public_ip and not force:
        return _my_public_ip
    override = os.environ.get("OBSCURA_MY_PUBLIC_IP", "").strip()
    if override:
        _my_public_ip = override
        log.info("Public IP set from OBSCURA_MY_PUBLIC_IP=%s", override)
        return _my_public_ip
    try:
        result = registry_request_json(f"{REGISTRY_URL}/whoami", timeout=5)
        ip = result.get("ip") if isinstance(result, dict) else None
        if ip:
            _my_public_ip = ip
            log.info("Learned public IP from registry /whoami: %s", ip)
            return ip
    except Exception as e:
        log.debug("Failed to learn public IP via /whoami: %s", e)
    return _my_public_ip


def is_private_peer(peer: dict | None) -> bool:
    """True if ``peer`` advertises a non-routable host literal.

    RFC1918 / loopback / link-local / multicast / unspecified addresses are
    not reachable from a different network, so advertising one as an intro
    point or proposing one as a rendezvous point strands any remote dialer:
    its frames have no path back to the host. ``OBSCURA_ALLOW_LAN_PEERS=1``
    disables the filter for fully-private testnets.
    """
    if not peer:
        return False
    host = peer.get("host")
    if not host:
        return False
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostnames are accepted as-is - we cannot resolve them without
        # potentially leaking a DNS query, and a hostname is at least
        # plausibly externally resolvable.
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified or ip.is_reserved
    )


def allow_lan_peers() -> bool:
    """``OBSCURA_ALLOW_LAN_PEERS=1`` opts back in to RFC1918 peers.

    Useful for fully-private testnets where every machine is on the same
    LAN and external reachability is irrelevant. Read fresh each call so
    tests can toggle the env var without monkey-patching.
    """
    return os.environ.get("OBSCURA_ALLOW_LAN_PEERS", "").strip().lower() in (
        "1", "true", "yes", "on",
    )

# Cloudflare (and some WAFs) return 403 for urllib's default User-Agent (Python-urllib/x.x).
_REGISTRY_UA = "Obscura47/1.0 (registry-client)"


def registry_headers(extra: dict | None = None) -> dict:
    h = {
        "User-Agent": _REGISTRY_UA,
        "Accept": "application/json",
    }
    if extra:
        h.update(extra)
    return h


# Back-compat alias for the previously private helper.
_registry_headers = registry_headers


class RegistryHTTPError(Exception):
    """Raised by registry_request_json when the registry response is not usable.

    ``kind`` discriminates between transport, http-status, and content-type
    failures so callers can surface specific diagnostics (e.g. distinguish
    a 404 descriptor lookup from a Cloudflare HTML fallback served because
    the deployed registry is missing /hs routes).
    """

    def __init__(self, kind: str, message: str, status: int | None = None,
                 content_type: str | None = None, body_preview: str | None = None):
        super().__init__(message)
        self.kind = kind  # "transport" | "http_status" | "content_type" | "json_decode"
        self.status = status
        self.content_type = content_type
        self.body_preview = body_preview


def registry_request_json(url: str, *, method: str = "GET",
                          data: bytes | None = None,
                          extra_headers: dict | None = None,
                          timeout: int = 10):
    """Make a registry HTTP call and return parsed JSON, or raise
    :class:`RegistryHTTPError` with a structured diagnosis.

    Centralising this means every caller benefits from:

    * the Obscura47 User-Agent header (Cloudflare 403s default urllib UAs)
    * a Content-Type guard so a Cloudflare/nginx HTML fallback page is
      reported as such instead of a generic JSON-decode failure
    * a short body preview in the error for easier triage
    """
    headers = registry_headers(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=registry_ssl_ctx())
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read() or b""
        except Exception:
            pass
        ct = e.headers.get("Content-Type", "") if e.headers else ""
        raise RegistryHTTPError(
            "http_status",
            f"{method} {url} → HTTP {e.code}",
            status=e.code,
            content_type=ct,
            body_preview=body[:200].decode(errors="replace"),
        ) from e
    except Exception as e:
        raise RegistryHTTPError(
            "transport", f"{method} {url} → {e}",
        ) from e

    with resp:
        ct = resp.headers.get("Content-Type", "")
        body = resp.read() or b""

    if "json" not in ct.lower():
        raise RegistryHTTPError(
            "content_type",
            f"{method} {url} returned non-JSON content-type {ct!r} - "
            f"the registry may be missing this endpoint and a reverse "
            f"proxy is serving a fallback page",
            status=200,
            content_type=ct,
            body_preview=body[:200].decode(errors="replace"),
        )

    try:
        return json.loads(body)
    except Exception as e:
        raise RegistryHTTPError(
            "json_decode",
            f"{method} {url} returned malformed JSON: {e}",
            content_type=ct,
            body_preview=body[:200].decode(errors="replace"),
        ) from e


def registry_ssl_ctx():
    """Return an SSL context honoring OBSCURA_TLS_VERIFY (None for http:// URLs)."""
    if not REGISTRY_URL.startswith("https://"):
        return None
    if TLS_VERIFY:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _capture_registration_classification(role: str, result: dict | None) -> None:
    """Record role_kind and primary_peer from a successful registration response.

    Siblings receive ``primary_peer`` so callers (the router) can pin it as
    the gateway first hop. Primaries clear any stale primary_peer cached
    from a prior sibling session.
    """
    if not isinstance(result, dict) or not result.get("ok"):
        return
    kind = result.get("role_kind")
    primary = result.get("primary_peer")
    with _registration_state_lock:
        if kind:
            _role_kind[role] = kind
        global _primary_peer
        if kind == "sibling" and primary:
            _primary_peer = primary
        elif kind == "primary":
            _primary_peer = None


def _attempt_registration(role: str, port: int, pub: str | None,
                          priv_key, ws_port: int | None, ws_tls: bool | None,
                          advertised_host: str | None) -> dict | None:
    """One round-trip to /register (+ /register/verify when challenged).

    Returns the parsed response dict on success, ``None`` on transport
    failure. Raises ``urllib.error.HTTPError`` for non-2xx HTTP responses
    so the caller can distinguish a 409 (slot-conflict) from other errors
    and decide whether to fall back to a LAN advertised_host.
    """
    global _my_public_ip
    body: dict = {"role": role, "port": port}
    if pub:
        body["pub"] = pub
    if ws_port:
        body["ws_port"] = ws_port
    if ws_tls is not None:
        body["ws_tls"] = ws_tls
    if advertised_host:
        body["advertised_host"] = advertised_host
    # Ride forward-brokering fields (want_forward / granted_forwards) along on
    # the existing /register round-trip. The registry ignores them unless they
    # apply (private host for want_forward; primary-of-NAT for granted_forwards).
    for k, v in _consume_forward_request_fields().items():
        body[k] = v

    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/register",
        data=data,
        headers=_registry_headers({"Content-Type": "application/json"}),
        method="POST",
    )
    ctx = registry_ssl_ctx()
    with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
        result = json.loads(resp.read())

    if result.get("ok"):
        _my_public_ip = result.get("your_ip") or _my_public_ip
        registered_host = result.get("registered_host") or body.get("advertised_host") or _my_public_ip
        log.info(f"Registered as {role} with registry (your_ip={_my_public_ip}, host={registered_host}, kind={result.get('role_kind')})")
        return result

    # Challenge-response flow
    challenge = result.get("challenge")
    peer_id = result.get("peer_id")
    if challenge and peer_id and priv_key and pub:
        from src.core.encryptions import ecdsa_sign
        signature = ecdsa_sign(priv_key, challenge.encode())

        verify_body = json.dumps({
            "peer_id": peer_id,
            "signature": signature,
        }).encode()
        verify_req = urllib.request.Request(
            f"{REGISTRY_URL}/register/verify",
            data=verify_body,
            headers=_registry_headers({"Content-Type": "application/json"}),
            method="POST",
        )
        with urllib.request.urlopen(verify_req, timeout=5, context=ctx) as verify_resp:
            verify_result = json.loads(verify_resp.read())

        if verify_result.get("ok"):
            _my_public_ip = verify_result.get("your_ip") or _my_public_ip
            registered_host = verify_result.get("registered_host") or body.get("advertised_host") or _my_public_ip
            log.info(f"Verified as {role} with registry (your_ip={_my_public_ip}, host={registered_host}, kind={verify_result.get('role_kind')})")
            return verify_result
        log.error(f"Verification failed: {verify_result}")
        return None
    log.warning(f"Challenge received but no private key to sign with")
    return None


def register_with_registry(role: str, port: int, pub: str | None = None,
                           priv_key=None, ws_port: int | None = None,
                           ws_tls: bool | None = None,
                           advertised_host: str | None = None):
    """
    Register this node with the bootstrap registry.
    If pub + priv_key are provided, performs ECDSA challenge-response auth.

    When the public (source-IP) slot is already held by another key behind
    the same NAT (HTTP 409), we transparently retry with our LAN address as
    ``advertised_host`` and register as an internal sibling instead. The
    chosen LAN address is cached per role so subsequent heartbeats skip
    the public attempt that we already know will conflict.
    """
    # Honor a sticky LAN address chosen by a prior 409 fallback.
    if advertised_host is None:
        with _registration_state_lock:
            advertised_host = _effective_advertised_host.get(role)

    try:
        result = _attempt_registration(role, port, pub, priv_key,
                                       ws_port, ws_tls, advertised_host)
        _capture_registration_classification(role, result)
        if isinstance(result, dict):
            _run_forward_provisioner(result.get("pending_forwards"))
        return result
    except urllib.error.HTTPError as e:
        if e.code != 409 or advertised_host is not None:
            log.error(f"Failed to register with registry: {e}")
            return None
        # Public slot is owned by another key behind our NAT. Fall back to a
        # sibling registration scoped to the LAN.
        lan_ip = _pick_local_lan_ip()
        if not lan_ip:
            log.error(f"Registry slot conflict and no LAN address detected; "
                      f"cannot fall back to sibling registration ({e})")
            return None
        log.info(f"Public-slot conflict on register; retrying as sibling under LAN {lan_ip}")
        try:
            result = _attempt_registration(role, port, pub, priv_key,
                                           ws_port, ws_tls, lan_ip)
        except Exception as e2:
            log.error(f"Sibling fallback registration failed: {e2}")
            return None
        if result and result.get("ok"):
            with _registration_state_lock:
                _effective_advertised_host[role] = lan_ip
        _capture_registration_classification(role, result)
        return result
    except Exception as e:
        log.error(f"Failed to register with registry: {e}")
        return None


def heartbeat_loop(role: str, port: int, pub: str | None = None,
                   priv_key=None, ws_port: int | None = None,
                   ws_tls: bool | None = None,
                   advertised_host: str | None = None):
    """Periodically re-register to keep this node alive in the registry.

    When the self-probe reports our WS port as unreachable (and the operator
    opted in via ``OBSCURA_REQUIRE_WS_REACHABLE=1``) we drop ``ws_port`` from
    the heartbeat so circuit builders stop picking us for WS hops they cannot
    actually complete. The suppression flips back as soon as the probe
    succeeds again.

    Exits when ``_heartbeat_state[role]['running']`` flips False (via
    ``stop_heartbeat``); that path also issues the signed deregister.
    """
    from src.core import peer_health
    last_advertised: bool | None = None
    while True:
        with _heartbeat_lock:
            st = _heartbeat_state.get(role)
            if st is not None and not st.get("running", True):
                return
        advertise_ws = ws_port is not None and peer_health.should_advertise_ws(role)
        if last_advertised is not None and advertise_ws != last_advertised:
            if advertise_ws:
                log.info(
                    "WS advertisement resumed for %s: self-probe now reports "
                    "ws_port=%s reachable",
                    role, ws_port,
                )
            else:
                log.warning(
                    "WS advertisement suppressed for %s: self-probe reports "
                    "ws_port=%s unreachable; heartbeat will omit ws_port until "
                    "the probe recovers",
                    role, ws_port,
                )
        last_advertised = advertise_ws

        effective_ws_port = ws_port if advertise_ws else None
        effective_ws_tls = ws_tls if advertise_ws else None
        result = register_with_registry(role, port, pub, priv_key=priv_key,
                                        ws_port=effective_ws_port,
                                        ws_tls=effective_ws_tls,
                                        advertised_host=advertised_host)
        # Capture the peer_id assigned by the registry - the deregister flow
        # needs it, and the registry constructs it from advertised_host+port
        # which we don't always know in advance (it may rewrite our host).
        if isinstance(result, dict) and result.get("peer_id"):
            with _heartbeat_lock:
                st = _heartbeat_state.setdefault(role, {"running": True})
                prior_peer_id = st.get("peer_id")
                st["peer_id"] = result["peer_id"]
            if prior_peer_id != result["peer_id"]:
                diag.set_node_id(result["peer_id"])
                diag.emit("register_ok", role=role, peer_id=result["peer_id"])
        time.sleep(REGISTRY_HEARTBEAT_INTERVAL)


def start_heartbeat(role: str, port: int, pub: str | None = None,
                    priv_key=None, ws_port: int | None = None,
                    ws_tls: bool | None = None,
                    advertised_host: str | None = None):
    """Start the heartbeat in a background daemon thread."""
    global _atexit_registered
    with _heartbeat_lock:
        _heartbeat_state[role] = {
            "running": True,
            "peer_id": None,
            "priv_key": priv_key,
        }
        if not _atexit_registered:
            atexit.register(_deregister_all_on_exit)
            _atexit_registered = True
    t = threading.Thread(
        target=heartbeat_loop,
        args=(role, port, pub),
        kwargs={
            "priv_key": priv_key,
            "ws_port": ws_port,
            "ws_tls": ws_tls,
            "advertised_host": advertised_host,
        },
        daemon=True,
    )
    t.start()
    return t


def deregister_with_registry(role: str) -> bool:
    """Send a signed deregister to the registry for ``role``.

    Returns True on a successful round-trip (including idempotent no-ops when
    the peer was already gone), False on any failure. Best-effort: callers
    should not block shutdown on this.
    """
    with _heartbeat_lock:
        st = _heartbeat_state.get(role)
        if not st:
            return False
        peer_id = st.get("peer_id")
        priv_key = st.get("priv_key")
    if not peer_id or priv_key is None:
        return False

    from src.core.encryptions import ecdsa_sign
    timestamp = time.time()
    message = f"deregister:{peer_id}:{timestamp}".encode()
    try:
        signature = ecdsa_sign(priv_key, message)
    except Exception as e:
        log.warning(f"Deregister signature failed for {role}: {e}")
        return False

    body = json.dumps({
        "peer_id": peer_id,
        "timestamp": timestamp,
        "signature": signature,
    }).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/deregister",
        data=body,
        headers=_registry_headers({"Content-Type": "application/json"}),
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5, context=registry_ssl_ctx()) as resp:
            result = json.loads(resp.read())
        log.info(f"Deregistered {role} ({peer_id}) from registry: {result}")
        diag.emit("deregister", role=role, peer_id=peer_id, ok=True,
                  deleted=bool(result.get("deleted")))
        return True
    except Exception as e:
        log.warning(f"Deregister failed for {role} ({peer_id}): {e}")
        diag.emit("deregister", role=role, peer_id=peer_id, ok=False, err=str(e))
        return False


def stop_heartbeat(role: str) -> bool:
    """Stop heartbeating for ``role`` and send a signed deregister.

    Used by the tray / GUI Disconnect button and by the host shutdown path.
    Safe to call repeatedly; subsequent calls are no-ops.
    """
    with _heartbeat_lock:
        st = _heartbeat_state.get(role)
        if not st or not st.get("running", True):
            return False
        st["running"] = False
    return deregister_with_registry(role)


def _deregister_all_on_exit():
    """atexit hook: signed deregister for every still-running role.

    Catches the case where the process exits via ``sys.exit`` or a returning
    main thread - signal handlers run in those paths too but only if the
    entry point installed any. atexit is the belt-and-suspenders backstop.
    """
    with _heartbeat_lock:
        roles = [r for r, st in _heartbeat_state.items() if st.get("running", True)]
    for role in roles:
        try:
            stop_heartbeat(role)
        except Exception as e:
            log.warning(f"atexit deregister failed for {role}: {e}")


def fetch_peers_from_registry(role_filter: str | None = None) -> List[Dict]:
    """Fetch the full peer list from the bootstrap registry."""
    url = f"{REGISTRY_URL}/peers"
    if role_filter:
        url += f"?role={role_filter}"
    req = urllib.request.Request(url, headers=_registry_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5, context=registry_ssl_ctx()) as resp:
            peers = json.loads(resp.read())
            return peers if isinstance(peers, list) else []
    except Exception as e:
        log.error(f"Failed to fetch peers from registry: {e}")
        return []


def _warm_peer_health(host: str, port: int) -> None:
    """Cheap TCP probe of a peer's WS port to seed peer_health.

    Runs in a worker thread so newly-discovered peers don't block the
    discovery loop. Without this seeding, the first circuit attempt
    after startup picks blindly from all advertised peers - including
    ones whose WS is firewalled - and we eat a ~30s timeout per dead
    peer before health tracking kicks in.
    """
    try:
        from src.core.peer_health import probe_tcp, mark_success, mark_failure
        ok, why = probe_tcp(host, port, timeout=3.0)
        if ok:
            mark_success(host, port)
        else:
            mark_failure(host, port, reason=f"discovery probe: {why}")
            mark_failure(host, port, reason=f"discovery probe: {why}")
    except Exception:
        pass


def merge_internet_peers(target_list: List[Dict], role_filter: str | None = None):
    """
    Fetch peers from the registry and merge them into a local peer list.
    `role_filter` can be "node", "exit", or None for all.
    Now parses ws_port from registry responses.
    """
    remote = fetch_peers_from_registry(role_filter=role_filter)
    now = time.time()
    newly_discovered: list[tuple[str, int]] = []
    for p in remote:
        if role_filter and p.get("role") != role_filter:
            continue
        entry = {"host": p["host"], "port": p["port"], "ts": now}
        if p.get("pub"):
            entry["pub"] = p["pub"]
        if p.get("ws_port"):
            entry["ws_port"] = p["ws_port"]
        if p.get("ws_tls"):
            entry["ws_tls"] = True
        before = len(target_list)
        _merge_peer(target_list, entry)
        if len(target_list) > before:
            log.info(f"Discovered {p.get('role', '?')} at {p['host']}:{p['port']}"
                     + (f" (ws:{p['ws_port']})" if p.get('ws_port') else ""))
            if entry.get("ws_port") and not is_self_peer(entry):
                newly_discovered.append((p["host"], int(p["ws_port"])))

    # Warm peer_health for new peers in the background so the very first
    # circuit doesn't blindly pick a peer whose WS port is firewalled.
    for host, ws_port in newly_discovered:
        threading.Thread(
            target=_warm_peer_health, args=(host, ws_port), daemon=True,
        ).start()

    # Expire old peers
    cutoff = now - PEER_EXPIRY_SECONDS
    target_list[:] = [p for p in target_list if p.get("ts", 0) >= cutoff]


def internet_discovery_loop(relay_peers: List[Dict], exit_peers: List[Dict], interval: int = 15):
    """Periodically fetch peers from the registry and merge into local lists."""
    while True:
        merge_internet_peers(relay_peers, role_filter="node")
        merge_internet_peers(exit_peers, role_filter="exit")
        time.sleep(interval)


def start_internet_discovery(relay_peers: List[Dict], exit_peers: List[Dict], interval: int = 15):
    """Start internet discovery in a background daemon thread."""
    t = threading.Thread(
        target=internet_discovery_loop,
        args=(relay_peers, exit_peers, interval),
        daemon=True,
    )
    t.start()
    return t


def _ecdsa_verify_signature(pub_pem: str, message_bytes: bytes, signature_b64: str) -> bool:
    """
    Verify an ECDSA signature on a message using a public key in PEM format.
    Returns True if signature is valid, False otherwise.
    """
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
        import base64

        # Import the public key
        pub_key = ECC.import_key(pub_pem)

        # Decode the signature from base64
        signature_bytes = base64.b64decode(signature_b64)

        # Verify the signature
        verifier = DSS.new(pub_key, mode='fips-186-3', encoding='binary')
        hash_obj = SHA256.new(message_bytes)
        verifier.verify(hash_obj, signature_bytes)
        return True
    except Exception as e:
        log.debug(f"Signature verification failed: {e}")
        return False


def check_network_status() -> dict:
    """
    Check the registry for network status including kill switch state.
    Returns a dict with at least 'kill_active' key.
    On any error, returns {"kill_active": False} (fail-open).
    """
    try:
        req = urllib.request.Request(
            f"{REGISTRY_URL}/network/status",
            headers=_registry_headers(),
            method="GET"
        )
        ctx = registry_ssl_ctx()
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read())
            return result if isinstance(result, dict) else {"kill_active": False}
    except Exception as e:
        log.debug(f"Failed to check network status: {e}")
        return {"kill_active": False}


def kill_switch_monitor(shutdown_callback: Callable[[str], None]):
    """
    Monitor the registry for kill switch activation.
    Runs in a loop, checking every KILL_SWITCH_CHECK_INTERVAL seconds.
    If kill_active is True, verifies the signature (if ADMIN_PUB_PEM is configured)
    and calls shutdown_callback(reason) if valid.
    """
    while True:
        try:
            status = check_network_status()
            if status.get("kill_active", False):
                reason = status.get("reason", "kill switch activated")
                timestamp = status.get("timestamp", "")
                signature = status.get("signature", "")

                # Verify signature if ADMIN_PUB_PEM is configured
                if ADMIN_PUB_PEM:
                    message = f"KILL:{reason}:{timestamp}"
                    if not _ecdsa_verify_signature(ADMIN_PUB_PEM, message.encode(), signature):
                        log.warning(f"Kill switch signature verification failed, ignoring")
                        time.sleep(KILL_SWITCH_CHECK_INTERVAL)
                        continue

                # Signature valid (or no verification configured), execute shutdown
                log.warning(f"Kill switch activated: {reason}")
                shutdown_callback(reason)
                break
        except Exception as e:
            log.error(f"Error in kill switch monitor: {e}")

        time.sleep(KILL_SWITCH_CHECK_INTERVAL)


def start_kill_switch_monitor(shutdown_callback: Callable[[str], None]):
    """Start the kill switch monitor in a daemon thread."""
    t = threading.Thread(
        target=kill_switch_monitor,
        args=(shutdown_callback,),
        daemon=True,
    )
    t.start()
    return t
