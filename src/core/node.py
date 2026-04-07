import socket
import threading
import json
import time
from src.core.router import Router
from src.core.encryptions import decrypt_message, onion_decrypt_with_priv, onion_decrypt_checked, ecc_load_or_create_keypair
from src.core.discover import listen_for_discovery, broadcast_discovery
from src.core.internet_discovery import start_heartbeat
from src.core.ws_transport import WSServer, get_ws_client
from src.utils.logger import get_logger
from src.utils.config import (
    NODE_MULTICAST_PORT as CFG_NODE_MULTICAST_PORT,
    DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL,
    ONION_ONLY, NODE_KEY_PATH, NODE_WS_PORT,
    WS_TLS_CERT, WS_TLS_KEY, WS_TLS_ACTIVE,
)

log = get_logger(__name__)

NODE_MULTICAST_PORT = CFG_NODE_MULTICAST_PORT  # Node discovery
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL  # Broadcast interval

class ObscuraNode:
    def __init__(self, host='0.0.0.0', port=5001):
        """
        Initialize a relay node that listens for encrypted messages.
        """
        self.host = host
        self.port = port
        self.ws_port = NODE_WS_PORT
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.peers = []
        # Load or create persistent node ECDH keypair for onion layer
        self.priv_key, self.pub_pem = ecc_load_or_create_keypair(NODE_KEY_PATH)

        # Reverse-channel registry: request_id -> send_back callable
        # When a tunnel CONNECT arrives on an inbound connection, we record
        # the send_back function (TCP socket writer or WS reverse_send) so
        # that later reverse_data / reverse_close frames can flow back
        # toward the proxy on the *same* connection — no new inbound connect.
        self._reverse_channels = {}
        self._reverse_lock = threading.Lock()

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Initialize global WS client for outbound WebSocket connections.
        # The on_receive callback handles reverse-channel frames arriving
        # on outbound WS connections (responses flowing back from downstream).
        def _ws_reverse_handler(message):
            try:
                frame = json.loads(message) if isinstance(message, str) else message
                if frame.get('type') in ('reverse_data', 'reverse_close'):
                    self._handle_reverse_frame(frame)
            except Exception as e:
                log.error("WS reverse frame error: %s", e)

        get_ws_client(self.priv_key, self.pub_pem, on_receive=_ws_reverse_handler)

        # Start discovery listener continuously
        threading.Thread(
            target=self.listen_for_nodes,
            daemon=True
        ).start()

        # Continuously broadcast discovery requests
        threading.Thread(
            target=self.continuous_discovery,
            daemon=True
        ).start()

        self.ws_tls_enabled = WS_TLS_ACTIVE

        # Register with internet bootstrap registry (with ws_port and priv_key for auth)
        start_heartbeat("node", self.port, self.pub_pem,
                        priv_key=self.priv_key, ws_port=self.ws_port,
                        ws_tls=self.ws_tls_enabled or None)

        # Start WebSocket server (dual-protocol; wss:// when TLS configured)
        self.ws_server = WSServer(
            self.host, self.ws_port,
            self.priv_key, self.pub_pem,
            on_frame=self._on_ws_frame,
            tls_cert=WS_TLS_CERT if WS_TLS_ACTIVE else None,
            tls_key=WS_TLS_KEY if WS_TLS_ACTIVE else None,
        )
        self.ws_server.start()

        log.info("Node Discovery started on port %s", NODE_MULTICAST_PORT)
        log.info("WebSocket server on port %s", self.ws_port)

        # Allow time for initial discovery
        time.sleep(5)

        # Create the router with updated peers
        self.router = Router(self, self.peers)

    def _on_ws_frame(self, message: str, reverse_send=None):
        """Handle a frame received via WebSocket (same logic as TCP)."""
        try:
            packet = json.loads(message)
            # Reverse-channel frames bypass normal onion processing
            if packet.get('type') in ('reverse_data', 'reverse_close'):
                self._handle_reverse_frame(packet)
                return
            self.process_frame(packet, send_back=reverse_send)
        except Exception as e:
            log.error("WS frame error: %s", e)

    def _handle_reverse_frame(self, frame):
        """Forward a reverse-channel response frame back toward the proxy.

        The frame is looked up by ``request_id`` in the stored reverse
        channels and written verbatim to the inbound connection that
        originally delivered the corresponding CONNECT frame.
        """
        if isinstance(frame, str):
            frame = json.loads(frame)
        req_id = frame.get('request_id', '')
        with self._reverse_lock:
            send_fn = self._reverse_channels.get(req_id)
        if send_fn:
            try:
                send_fn(json.dumps(frame))
                log.debug("Reverse-channel forwarded | request_id=%s", req_id)
            except Exception as e:
                log.error("Reverse-channel send error | request_id=%s | %s", req_id, e)
        else:
            log.warning("No reverse channel for request_id=%s", req_id)
        if frame.get('type') == 'reverse_close':
            with self._reverse_lock:
                self._reverse_channels.pop(req_id, None)

    def process_frame(self, incoming_packet: dict, send_back=None):
        """Process an incoming encrypted frame (shared by TCP and WebSocket handlers).

        ``send_back`` is an optional callable that writes data back to the
        inbound connection this frame arrived on.  It is stored as a
        *reverse channel* on tunnel CONNECT frames so that response frames
        can later flow back through the same connection path.
        """
        encrypted_data = incoming_packet.get("encrypted_data", None)
        if not encrypted_data:
            log.warning("No encrypted data found. Dropping message.")
            return

        # Try onion layer first; fall back to legacy frame encryption
        decrypted_message = onion_decrypt_checked(self.priv_key, encrypted_data)
        if decrypted_message is None:
            if ONION_ONLY:
                log.warning("Onion-only mode: legacy frame rejected")
                return
            decrypted_message = decrypt_message(encrypted_data)
            if decrypted_message is None:
                log.error("Decryption failed. Dropping message.")
                return

        try:
            layer = json.loads(decrypted_message)
        except Exception as e:
            log.error("Frame decode error: %s", e)
            return

        # Nested onion layer: next_hop/inner or terminal payload
        if isinstance(layer, dict) and ('payload' in layer or 'next_hop' in layer or 'inner' in layer):
            if 'payload' in layer:
                payload = layer['payload'] or {}
                req_id = payload.get("request_id", "") if isinstance(payload, dict) else ""
                log.info("Final destination reached at %s:%s | request_id=%s", self.host, self.port, req_id)
                return
            next_hop = layer.get('next_hop')
            inner = layer.get('inner')
            if not next_hop or inner is None:
                log.warning("Malformed onion layer; dropping")
                return
            if isinstance(next_hop, dict):
                encrypted_inner = inner if isinstance(inner, str) else json.dumps(inner)
                self.router.send_to_next_hop(next_hop, encrypted_inner)
                return
            log.warning("Invalid next_hop format; dropping")
            return

        # Tunnel envelope (type + route) — walk the route and forward
        if isinstance(layer, dict) and layer.get('type') in ('connect', 'data', 'close') and isinstance(layer.get('route'), list):
            route = layer['route']
            req_id = layer.get("request_id", "")
            # Store the inbound connection as a reverse channel on CONNECT
            if layer['type'] == 'connect' and send_back and req_id:
                with self._reverse_lock:
                    self._reverse_channels[req_id] = send_back
                log.info("Stored reverse channel for request_id=%s", req_id)
            if route:
                next_hop = route.pop(0)
                log.info("Forwarding tunnel frame (%s) to %s:%s | request_id=%s", layer['type'], next_hop['host'], next_hop['port'], req_id)
                self.router.forward_message(next_hop, layer)
            else:
                log.info("Tunnel frame with empty route at %s:%s | request_id=%s", self.host, self.port, req_id)
            # Clean up reverse channel on CLOSE
            if layer['type'] == 'close' and req_id:
                with self._reverse_lock:
                    self._reverse_channels.pop(req_id, None)
            return

        # Legacy envelope with explicit route
        if isinstance(layer, dict) and 'route' in layer:
            hop_count = len(layer.get("route", []))
            req_id = layer.get("request_id", "")
            log.info("Received at %s:%s | hops_remaining=%d | request_id=%s", self.host, self.port, hop_count, req_id)
            if layer["route"]:
                next_hop = layer["route"].pop(0)
                log.info("Forwarding to %s:%s | request_id=%s", next_hop['host'], next_hop['port'], req_id)
                self.router.forward_message(next_hop, layer)
            else:
                log.info("Final destination reached at %s:%s | request_id=%s", self.host, self.port, req_id)
            return

        log.warning("Unrecognized frame shape; dropping")

    def listen_for_nodes(self):
        """Continuously listen for other nodes' discovery responses."""
        log.info("Listening for discovery on 50002")
        listen_for_discovery(self.peers, self.port, NODE_MULTICAST_PORT, extra_fields={'pub': self.pub_pem})

    def continuous_discovery(self):
        """Continuously broadcast discovery requests every few seconds."""
        while self.running:
            log.info("Broadcasting discovery request")
            broadcast_discovery(NODE_MULTICAST_PORT)
            time.sleep(DISCOVERY_INTERVAL)

    def start_server(self):
        """Start the node server to listen for incoming encrypted messages (legacy TCP)."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)
            log.info("Node started at %s:%s (TCP), waiting for connections", self.host, self.port)
        except OSError:
            log.warning("Port %s is already in use, trying another port", self.port)
            self.port += 1
            self.start_server()
            return

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                log.info("Connection from %s", addr)
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                log.warning("Node shutting down")
                break

    def shutdown(self):
        """Gracefully stop the node."""
        self.running = False
        try:
            self.server_socket.close()
        except Exception:
            pass
        if hasattr(self, 'ws_server'):
            try:
                self.ws_server.stop()
            except Exception:
                pass
        log.warning("Node %s:%s shut down", self.host, self.port)

    def handle_client(self, client_socket):
        """Handles incoming encrypted messages from other nodes (legacy TCP).

        A thread-safe ``send_back`` closure is created for this socket so
        that reverse-channel responses can be written back on the same
        inbound TCP connection.
        """
        _send_lock = threading.Lock()

        def _tcp_send_back(data_str):
            """Write *data_str* back to the inbound TCP socket (reverse channel)."""
            try:
                with _send_lock:
                    client_socket.sendall((data_str + "\n").encode())
            except Exception:
                pass

        try:
            buffer = ""
            while True:
                chunk = client_socket.recv(4096).decode()
                if not chunk:
                    break
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if not line:
                        continue
                    incoming_packet = json.loads(line)
                    # Reverse-channel frames skip decryption
                    if incoming_packet.get('type') in ('reverse_data', 'reverse_close'):
                        self._handle_reverse_frame(incoming_packet)
                    else:
                        self.process_frame(incoming_packet, send_back=_tcp_send_back)

        except Exception as e:
            log.error("Error handling client: %s", e)
        finally:
            client_socket.close()

    def run(self):
        """Start the node server in a separate daemon thread."""
        server_thread = threading.Thread(target=self.start_server, daemon=True)
        server_thread.start()

if __name__ == "__main__":
    node = ObscuraNode(port=5001)
    node.run()

    # Allow discovery to happen continuously
    while True:
        time.sleep(1)
