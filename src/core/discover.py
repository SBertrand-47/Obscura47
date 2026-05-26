import socket
import json
import struct
import time
from typing import List, Dict
from src.utils.config import DISCOVERY_PORT as CFG_DISCOVERY_PORT, NODE_DISCOVERY_PORT as CFG_NODE_DISCOVERY_PORT, EXIT_DISCOVERY_PORT as CFG_EXIT_DISCOVERY_PORT, PEER_EXPIRY_SECONDS
from src.utils.logger import get_logger

log = get_logger(__name__)

MULTICAST_GROUP = "239.255.255.250"
DISCOVERY_PORT = CFG_DISCOVERY_PORT  # Clients/Proxy discovery
NODE_MULTICAST_PORT = CFG_NODE_DISCOVERY_PORT  # Nodes discovery
EXIT_NODE_MULTICAST_PORT = CFG_EXIT_DISCOVERY_PORT  # Exit node discovery

# --- TOFU key pinning ---
# Maps (host, port) -> {"pub": pem, "first_seen": ts}
# If a peer re-announces with a different public key, it's flagged and rejected.
_pinned_keys: Dict[tuple, Dict] = {}


def _validate_peer_key(host: str, port: int, pub_pem: str | None) -> bool:
    """Trust-On-First-Use: accept a peer's key on first contact, reject changes."""
    if pub_pem is None:
        return True  # no key to pin
    key = (host, port)
    if key not in _pinned_keys:
        _pinned_keys[key] = {"pub": pub_pem, "first_seen": time.time()}
        return True
    if _pinned_keys[key]["pub"] == pub_pem:
        return True
    log.warning(
        f"TOFU violation: {host}:{port} changed public key "
        f"(pinned since {_pinned_keys[key]['first_seen']:.0f}). Rejecting peer."
    )
    return False


def _peer_matches(existing: Dict, new_peer: Dict) -> bool:
    if existing.get("host") == new_peer.get("host") and existing.get("port") == new_peer.get("port"):
        return True
    new_pub = new_peer.get("pub")
    return bool(new_pub and existing.get("pub") == new_pub)


def _merge_peer(peers: List[Dict], new_peer: Dict) -> None:
    """Merge a discovered peer into the list, deduping by endpoint or pubkey.

    Nodes may keep the same long-lived identity while their advertised TCP port
    changes. Treating ``pub`` as identity when available prevents one physical
    node from being counted twice under old/new ports.
    """
    match_idx = None
    duplicate_idxs: list[int] = []
    for idx, peer in enumerate(list(peers)):
        if _peer_matches(peer, new_peer):
            if match_idx is None:
                match_idx = idx
            else:
                duplicate_idxs.append(idx)

    is_new = match_idx is None
    if is_new:
        peers.append(dict(new_peer))
    else:
        merged = dict(peers[match_idx])
        for key, value in new_peer.items():
            if value is not None:
                merged[key] = value
        peers[match_idx] = merged

    for idx in reversed(duplicate_idxs):
        peers.pop(idx)

    # Warm peer_health for genuinely-new LAN-discovered peers. Without
    # this, a peer that advertises an unreachable IP (e.g. a VPN-only
    # interface) keeps getting picked for circuits until enough send
    # attempts have failed for the cooldown to engage - meanwhile the
    # user's traffic stalls. The probe is fire-and-forget so the
    # discovery listener never blocks on it.
    if is_new:
        _kick_health_probe(new_peer)


def _kick_health_probe(peer: Dict) -> None:
    """Best-effort: spawn a background TCP probe of ``peer``'s WS port.

    LAN discovery messages don't always carry ``ws_port``; fall back to
    the configured default so a misconfigured peer (advertising an
    unreachable IP on the standard node WS port) still gets caught.
    """
    host = peer.get("host")
    if not host:
        return
    ws_port = peer.get("ws_port")
    if not ws_port:
        try:
            from src.utils.config import NODE_WS_PORT
            ws_port = NODE_WS_PORT
        except Exception:
            return
    try:
        from src.core.internet_discovery import is_self_peer
        if is_self_peer({"host": host, "port": peer.get("port"), "pub": peer.get("pub")}):
            return
    except Exception:
        pass

    def _probe():
        try:
            from src.core.peer_health import probe_tcp, mark_success, mark_failure
            ok, why = probe_tcp(host, int(ws_port), timeout=3.0)
            if ok:
                mark_success(host, int(ws_port))
            else:
                mark_failure(host, int(ws_port), reason=f"discovery probe: {why}")
                mark_failure(host, int(ws_port), reason=f"discovery probe: {why}")
        except Exception:
            pass

    import threading as _t
    _t.Thread(target=_probe, daemon=True).start()

def get_local_ip():
    """Returns the machine's LAN IP (avoids 127.0.0.1)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

def broadcast_discovery(multicast_port=DISCOVERY_PORT):
    """Broadcasts a discovery request to find other nodes or clients."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            message = json.dumps({"type": "discovery_request"}).encode()
            sock.sendto(message, (MULTICAST_GROUP, multicast_port))
            log.info(f"Sent multicast discovery request on port {multicast_port}")
    except Exception as e:
        log.error(f"Error broadcasting discovery request: {e}")

def listen_for_discovery(peers: List[Dict], local_port=5001, multicast_port=DISCOVERY_PORT, extra_fields: Dict | None = None):
    """Listens for discovery requests and responds with node info.

    Wrapped in an outer recreate-loop so that a fatal OSError on the UDP
    socket (e.g. a Windows ICMP-port-unreachable echo that corrupts socket
    state despite SIO_UDP_CONNRESET) drops back to fresh socket setup
    instead of silently killing discovery for the process lifetime.
    """
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass
                _suppress_icmp_connreset(sock)
                sock.bind(("", multicast_port))

                mreq = struct.pack("=4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                log.info(f"Listening for discovery on {MULTICAST_GROUP}:{multicast_port}")

                advertised_ip = get_local_ip()

                while True:
                    try:
                        data, addr = sock.recvfrom(1024)
                        message = json.loads(data.decode())

                        log.info(f"Received discovery message from {addr}: {message}")

                        if message.get("type") == "discovery_request":
                            resp = {
                                "type": "discovery_response",
                                "host": advertised_ip,
                                "port": local_port
                            }
                            if isinstance(extra_fields, dict):
                                # Only include JSON-serializable fields
                                for k, v in extra_fields.items():
                                    resp[k] = v
                            response = json.dumps(resp).encode()
                            # Reply directly to requester
                            sock.sendto(response, addr)
                            # Also echo response to multicast so passive observers (e.g., proxy) can learn peers
                            try:
                                sock.sendto(response, (MULTICAST_GROUP, multicast_port))
                            except Exception:
                                pass
                            log.info(f"Responded to discovery from {addr[0]} with {advertised_ip}:{local_port}")

                        elif message.get("type") == "discovery_response":
                            new_peer = {"host": message["host"], "port": message["port"], "ts": time.time()}
                            if "pub" in message:
                                new_peer["pub"] = message["pub"]
                            is_self = (
                                new_peer["host"] == advertised_ip
                                and new_peer["port"] == local_port
                            )
                            if not is_self:
                                # TOFU: reject if public key changed
                                if not _validate_peer_key(new_peer["host"], new_peer["port"], new_peer.get("pub")):
                                    continue
                                before = len(peers)
                                _merge_peer(peers, new_peer)
                                if len(peers) > before:
                                    log.info(f"Discovered new peer: host={new_peer['host']}, port={new_peer['port']}")

                            # Expire old peers
                            cutoff = time.time() - PEER_EXPIRY_SECONDS
                            peers[:] = [p for p in peers if p.get("ts", 0) >= cutoff]

                    except json.JSONDecodeError:
                        log.warning("Received malformed discovery message. Ignoring.")
                    except OSError as e:
                        # Windows surfaces WSAECONNRESET (10054) on a UDP recv
                        # when an earlier unicast sendto provoked an ICMP
                        # 'port unreachable' from a peer whose ephemeral port
                        # already closed. SIO_UDP_CONNRESET=False is supposed
                        # to swallow this but isn't always honored in time.
                        # The error is benign: skip the log spam, keep looping.
                        if getattr(e, "winerror", None) == 10054:
                            log.debug(
                                "Discovery listener (port %s): benign ICMP-unreachable echo: %s",
                                multicast_port, e,
                            )
                            continue
                        # Anything else is genuinely unusual - drop to the outer
                        # loop so the socket is recreated, matching the
                        # observe_discovery pattern.
                        log.warning(
                            "Socket error in discovery listener (port %s): %s - recreating socket",
                            multicast_port, e,
                        )
                        break
                    except Exception as e:
                        log.warning(f"Error in discovery listener: {e}")
                        time.sleep(1)

        except Exception as e:
            log.error(f"Error setting up discovery listener: {e}")
        time.sleep(2)

def _suppress_icmp_connreset(sock):
    """
    On Windows, UDP sockets raise WinError 10054 (WSAECONNRESET) when an ICMP
    'port unreachable' is received. Suppress this so multicast observers don't
    get stuck in an error loop. No-op on other platforms.

    Logs at DEBUG when the ioctl rejects the call so a host where suppression
    isn't actually installing is diagnosable instead of silently noisy.
    """
    SIO_UDP_CONNRESET = getattr(socket, "SIO_UDP_CONNRESET", None)
    if SIO_UDP_CONNRESET is None:
        return
    try:
        sock.ioctl(SIO_UDP_CONNRESET, False)
    except Exception as e:
        log.debug("SIO_UDP_CONNRESET ioctl failed: %s", e)


def observe_discovery(peers: List[Dict], multicast_port=DISCOVERY_PORT):
    """
    Passive discovery listener: observes discovery responses on a multicast
    channel and appends them to `peers` without responding/advertising self.
    This is useful for roles that should not announce themselves on a given
    channel (e.g., proxy observing nodes/exits).
    """
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass
                _suppress_icmp_connreset(sock)
                sock.bind(("", multicast_port))

                mreq = struct.pack("=4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                log.info(f"Observing discovery on {MULTICAST_GROUP}:{multicast_port}")

                advertised_ip = get_local_ip()

                while True:
                    try:
                        data, addr = sock.recvfrom(1024)
                        message = json.loads(data.decode())

                        if message.get("type") == "discovery_response":
                            new_peer = {"host": message["host"], "port": message["port"], "ts": time.time()}
                            if "pub" in message:
                                new_peer["pub"] = message["pub"]
                            # Passive observers should accept peers on the same
                            # host when they advertise a different service port.
                            # This lets a local proxy discover co-hosted relays
                            # and exits instead of hiding them by IP alone.
                            if not _validate_peer_key(new_peer["host"], new_peer["port"], new_peer.get("pub")):
                                continue
                            before = len(peers)
                            _merge_peer(peers, new_peer)
                            if len(peers) > before:
                                log.info(f"Observed peer: host={new_peer['host']}, port={new_peer['port']} (from {addr[0]})")

                            # Expire old peers
                            cutoff = time.time() - PEER_EXPIRY_SECONDS
                            peers[:] = [p for p in peers if p.get("ts", 0) >= cutoff]
                    except json.JSONDecodeError:
                        continue
                    except OSError as e:
                        # WSAECONNRESET (10054) is a benign Windows quirk: an
                        # ICMP 'port unreachable' from a unicast peer surfaces
                        # on the next recv even when SIO_UDP_CONNRESET=False is
                        # installed. Don't tear down the socket for that.
                        if getattr(e, "winerror", None) == 10054:
                            log.debug(
                                "observe_discovery (port %s): benign ICMP-unreachable echo: %s",
                                multicast_port, e,
                            )
                            continue
                        # Anything else might have corrupted the socket state;
                        # break out so the outer loop recreates it.
                        log.warning(f"Socket error in observe_discovery (port {multicast_port}): {e} - recreating socket")
                        break
                    except Exception as e:
                        log.warning(f"Error in observe_discovery: {e}")
                        time.sleep(1)
        except Exception as e:
            log.error(f"Error setting up passive discovery observer: {e}")
        time.sleep(2)
