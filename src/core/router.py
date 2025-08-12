import random
import json
import socket
import time
import base64
from src.core.encryptions import encrypt_message, decrypt_message, onion_encrypt_for_peer
from src.utils.config import FRAME_RETRY_ATTEMPTS, FRAME_RETRY_BASE_DELAY_MS, MESSAGE_ROUTE_RETRIES, CHANNEL_QUEUE_MAX, CHANNEL_WRITE_TIMEOUT, CHANNEL_IDLE_CLOSE_SECONDS, ONION_ONLY

# Router-level metrics
FRAME_RETRIES = 0
MESSAGE_REROUTES = 0
TUNNEL_SOCKETS = {}  # (request_id, host, port) -> {'sock': socket, 'last': ts, 'q': list}

def get_router_metrics():
    return { 'frame_retries': FRAME_RETRIES, 'message_reroutes': MESSAGE_REROUTES }

"""
Encryption is now provided by src.core.encryptions to decouple concerns.
"""

class Router:
    def __init__(self, node, peers):
        """
        Initializes the router with a node instance and a list of peers.
        `peers` is a list of dictionaries: [{host, port}, ...].
        """
        self.node = node
        self.peers = peers

    def build_random_route(self, hops=3):
        """
        Generates a random path of nodes for relaying messages.
        If there aren't enough peers, use as many as available.
        """
        if len(self.peers) < hops:
            print("⚠️ Not enough peers for full hop count!")
            hops = len(self.peers)
        return random.sample(self.peers, hops) if hops > 0 else []

    def relay_message(self, data, destination, return_path=None, request_id=None):
        """
        Sends a message to a destination via a random route.
        If hop public keys are available, build onion layers so each hop learns only its next hop.
        """
        # Build a route through random peers and append the final (exit) node
        route = self.build_random_route()
        if destination:
            route.append(destination)

        if not route:
            print("⚠️ No peers/routes available. Message not sent.")
            return

        # Onion layering if all hops publish pub keys
        can_onion = all(isinstance(h, dict) and h.get('pub') for h in route)
        if can_onion:
            try:
                payload = {"data": data}
                if return_path is not None:
                    payload["return_path"] = return_path
                if request_id is not None:
                    payload["request_id"] = request_id

                inner = payload
                for i in range(len(route) - 1, -1, -1):
                    next_hop = route[i + 1] if i < len(route) - 1 else None
                    if next_hop is None:
                        layer_plain = {"payload": inner}
                    else:
                        layer_plain = {"next_hop": next_hop, "inner": inner}
                    sealed = onion_encrypt_for_peer(route[i]['pub'], json.dumps(layer_plain))
                    inner = sealed

                first_route = [route[0]]
                envelope = {"encrypted_data": inner}
                if not _send_frame_via_route(first_route, envelope):
                    print("❌ relay_message (onion) failed to send to first hop")
                return
            except Exception as e:
                print(f"⚠️ Onion build failed, falling back: {e}")

        # Fallback legacy path with visible route
        if ONION_ONLY:
            print("❌ Onion-only mode: missing pubkeys; dropping message")
            return
        envelope = {
            "data": data,
            "route": route,
            "return_path": return_path,
            "request_id": request_id,
        }
        full_route = list(route)
        attempts = 0
        sent = False
        global MESSAGE_REROUTES
        while attempts < MESSAGE_ROUTE_RETRIES:
            sent = _send_frame_via_route(full_route, envelope)
            if sent:
                break
            attempts += 1
            full_route = self.build_random_route()
            if destination:
                full_route.append(destination)
            MESSAGE_REROUTES += 1
        if attempts >= MESSAGE_ROUTE_RETRIES and not sent:
            print("❌ relay_message failed after route retries")

    def forward_message(self, next_node, message_content):
        """
        Re-encrypts the updated message_content (already a dict),
        then sends to the next hop in the route.
        """
        # Persistent tunnel frames reuse a per-request socket to next hop
        if isinstance(message_content, dict) and message_content.get('type') in ('connect', 'data', 'close') and message_content.get('request_id'):
            payload = json.dumps(message_content)
            encrypted = encrypt_message(payload)
            self._send_to_next_hop_persistent(next_node, encrypted, message_content['request_id'], is_close=(message_content.get('type') == 'close'))
            return
        new_encrypted = encrypt_message(json.dumps(message_content))
        self.send_to_next_hop(next_node, new_encrypted)

    def _send_to_next_hop_persistent(self, next_node, encrypted_message, request_id: str, is_close: bool = False):
        if not hasattr(self, '_tunnel_sockets'):
            self._tunnel_sockets = {}
        key = (request_id, next_node['host'], next_node['port'])
        entry = self._tunnel_sockets.get(key)
        try:
            if entry is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.connect((next_node['host'], next_node['port']))
                entry = {'sock': sock, 'last': time.time(), 'q': []}
                self._tunnel_sockets[key] = entry
            # queue and flush with backpressure
            pkt = (json.dumps({"encrypted_data": encrypted_message}) + "\n").encode()
            if len(entry['q']) >= CHANNEL_QUEUE_MAX:
                raise RuntimeError('channel queue overflow')
            entry['q'].append(pkt)
            deadline = time.time() + CHANNEL_WRITE_TIMEOUT
            while entry['q']:
                if time.time() > deadline:
                    raise TimeoutError('channel write timeout')
                chunk = entry['q'][0]
                sent = entry['sock'].send(chunk)
                if sent == len(chunk):
                    entry['q'].pop(0)
                    entry['last'] = time.time()
                else:
                    entry['q'][0] = chunk[sent:]
                    time.sleep(0.01)
            print(f"📤 Sent (persist) to {next_node['host']}:{next_node['port']}")
            if is_close:
                ent = self._tunnel_sockets.pop(key, None)
                try:
                    if ent and ent.get('sock'):
                        ent['sock'].close()
                except Exception:
                    pass
        except Exception as e:
            try:
                ent = self._tunnel_sockets.pop(key, None)
                if ent and ent.get('sock'):
                    ent['sock'].close()
            except Exception:
                pass
            print(f"❌ Persistent send error to {next_node}: {e}")

    def send_to_next_hop(self, next_node, encrypted_message):
        """
        Sends an already-encrypted message to the next hop.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((next_node['host'], next_node['port']))
                # Wrap the encrypted data in JSON for transport
                packet = {"encrypted_data": encrypted_message}
                sock.send((json.dumps(packet) + "\n").encode())
                print(f"📤 Sent encrypted message to {next_node['host']}:{next_node['port']}")
        except Exception as e:
            print(f"❌ Error sending to {next_node}: {e}")

def direct_relay_message(data, destination, peers, return_path=None, request_id=None):
    """
    A top-level helper for modules (like `proxy.py`) that just want
    to relay a message without manually instantiating a Router.
    """
    r = Router(node=None, peers=peers)
    r.relay_message(data, destination, return_path=return_path, request_id=request_id)

def build_route47(peers, min_hops: int = 4, max_hops: int = 7):
    """Build a route with length in the range [4,7] when available."""
    if not peers:
        return []
    hop_target = random.randint(min_hops, max_hops)
    hop_target = min(hop_target, len(peers))
    if hop_target <= 0:
        return []
    return random.sample(peers, hop_target)

def _send_frame_via_route(route, envelope):
    """Encrypt envelope and send to the first hop of route (newline-delimited packet)."""
    if not route:
        print("⚠️ No route; cannot send frame")
        return
    # Use onion layer if next hop published a public key
    next_hop = route[0]
    next_pub = next_hop.get('pub') if isinstance(next_hop, dict) else None
    payload = json.dumps(envelope)
    encrypted = onion_encrypt_for_peer(next_pub, payload) if next_pub else encrypt_message(payload)
    first_hop = route[0]
    attempt = 0
    delay_ms = FRAME_RETRY_BASE_DELAY_MS
    global FRAME_RETRIES, TUNNEL_SOCKETS
    # Detect tunnel frame and reuse persistent socket to first hop
    is_tunnel = isinstance(envelope, dict) and envelope.get('type') in ('connect', 'data', 'close') and envelope.get('request_id')
    key = (envelope['request_id'], first_hop['host'], first_hop['port']) if is_tunnel else None
    while attempt < FRAME_RETRY_ATTEMPTS:
        try:
            if is_tunnel:
                entry = TUNNEL_SOCKETS.get(key)
                if entry is None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    sock.connect((first_hop['host'], first_hop['port']))
                    entry = {'sock': sock, 'last': time.time(), 'q': []}
                    TUNNEL_SOCKETS[key] = entry
                # Backpressure queue
                if len(entry['q']) >= CHANNEL_QUEUE_MAX:
                    raise RuntimeError('channel queue overflow')
                entry['q'].append((json.dumps({"encrypted_data": encrypted}) + "\n").encode())
                # Flush queue
                deadline = time.time() + CHANNEL_WRITE_TIMEOUT
                while entry['q']:
                    if time.time() > deadline:
                        raise TimeoutError('channel write timeout')
                    chunk = entry['q'][0]
                    sent = entry['sock'].send(chunk)
                    if sent == len(chunk):
                        entry['q'].pop(0)
                        entry['last'] = time.time()
                    else:
                        # partial write; keep remaining in place
                        entry['q'][0] = chunk[sent:]
                        time.sleep(0.01)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((first_hop['host'], first_hop['port']))
                    packet = {"encrypted_data": encrypted}
                    sock.send((json.dumps(packet) + "\n").encode())
            print(f"📤 Sent frame to {first_hop['host']}:{first_hop['port']}")
            if is_tunnel and envelope.get('type') == 'close':
                try:
                    ent = TUNNEL_SOCKETS.pop(key, None)
                    if ent and ent.get('sock'):
                        ent['sock'].close()
                except Exception:
                    pass
            return True
        except Exception as e:
            attempt += 1
            FRAME_RETRIES += 1
            # If persistent socket used, drop it on failure
            if is_tunnel:
                ent = TUNNEL_SOCKETS.pop(key, None)
                try:
                    if ent and ent.get('sock'):
                        ent['sock'].close()
                except Exception:
                    pass
            jitter = random.uniform(0, delay_ms * 0.2)
            time.sleep((delay_ms + jitter) / 1000.0)
            delay_ms *= 2
    print(f"❌ Failed to send frame to {first_hop['host']}:{first_hop['port']} after {FRAME_RETRY_ATTEMPTS} attempts")
    return False

def channel_idle_sweeper():
    while True:
        time.sleep(5)
        now = time.time()
        for k, ent in list(TUNNEL_SOCKETS.items()):
            try:
                if now - ent.get('last', now) > CHANNEL_IDLE_CLOSE_SECONDS:
                    s = TUNNEL_SOCKETS.pop(k, None)
                    if s and s.get('sock'):
                        s['sock'].close()
            except Exception:
                pass

def start_tunnel(destination, peers, request_id: str, host: str, port: int, return_path: dict, route=None):
    """Start a tunnel by sending a CONNECT_INIT frame along a fixed route."""
    if route is None:
        route = build_route47(peers)
    full_route = list(route) + [destination]
    envelope = {
        "type": "connect",
        "host": host,
        "port": port,
        "request_id": request_id,
        "return_path": return_path,
        "route": full_route,
    }
    _send_frame_via_route(full_route, envelope)
    return route

def send_tunnel_data(destination, route, request_id: str, chunk_b64: str):
    full_route = list(route) + [destination]
    envelope = {
        "type": "data",
        "request_id": request_id,
        "chunk": chunk_b64,
        "route": full_route,
    }
    _send_frame_via_route(full_route, envelope)

def close_tunnel(destination, route, request_id: str):
    full_route = list(route) + [destination]
    envelope = {
        "type": "close",
        "request_id": request_id,
        "route": full_route,
    }
    _send_frame_via_route(full_route, envelope)
