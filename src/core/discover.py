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
    """Listens for discovery requests and responds with node info."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
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
                        if new_peer["host"] != advertised_ip:
                            # TOFU: reject if public key changed
                            if not _validate_peer_key(new_peer["host"], new_peer["port"], new_peer.get("pub")):
                                continue
                            # Update or insert
                            for idx, p in enumerate(list(peers)):
                                if p["host"] == new_peer["host"] and p["port"] == new_peer["port"]:
                                    peers[idx]["ts"] = new_peer["ts"]
                                    break
                            else:
                                peers.append(new_peer)
                                log.info(f"Discovered new peer: host={new_peer['host']}, port={new_peer['port']}")

                        # Expire old peers
                        cutoff = time.time() - PEER_EXPIRY_SECONDS
                        peers[:] = [p for p in peers if p.get("ts", 0) >= cutoff]

                except json.JSONDecodeError:
                    log.warning("Received malformed discovery message. Ignoring.")
                except Exception as e:
                    log.warning(f"Error in discovery listener: {e}")
                    time.sleep(1)

    except Exception as e:
        log.error(f"Error setting up discovery listener: {e}")

def observe_discovery(peers: List[Dict], multicast_port=DISCOVERY_PORT):
    """
    Passive discovery listener: observes discovery responses on a multicast
    channel and appends them to `peers` without responding/advertising self.
    This is useful for roles that should not announce themselves on a given
    channel (e.g., proxy observing nodes/exits).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
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
                        if new_peer["host"] != advertised_ip:
                            # TOFU: reject if public key changed
                            if not _validate_peer_key(new_peer["host"], new_peer["port"], new_peer.get("pub")):
                                continue
                            # Update or insert
                            for idx, p in enumerate(list(peers)):
                                if p["host"] == new_peer["host"] and p["port"] == new_peer["port"]:
                                    peers[idx]["ts"] = new_peer["ts"]
                                    break
                            else:
                                peers.append(new_peer)
                                log.info(f"Observed peer: host={new_peer['host']}, port={new_peer['port']} (from {addr[0]})")

                        # Expire old peers
                        cutoff = time.time() - PEER_EXPIRY_SECONDS
                        peers[:] = [p for p in peers if p.get("ts", 0) >= cutoff]
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    log.warning(f"Error in observe_discovery: {e}")
                    time.sleep(1)
    except Exception as e:
        log.error(f"Error setting up passive discovery observer: {e}")
