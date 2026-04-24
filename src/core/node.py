import socket
import threading
import json
import time
import sys
from src.core.router import Router
from src.core.encryptions import onion_decrypt_checked, ecc_load_or_create_keypair, onion_encrypt_for_peer
from src.core.discover import listen_for_discovery, broadcast_discovery
from src.core.internet_discovery import start_heartbeat, start_kill_switch_monitor
from src.core.ws_transport import WSServer, WSClient
from src.utils.logger import get_logger
from src.utils.config import (
    NODE_MULTICAST_PORT as CFG_NODE_MULTICAST_PORT,
    DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL,
    NODE_KEY_PATH, NODE_WS_PORT,
    WS_TLS_CERT, WS_TLS_KEY, WS_TLS_ACTIVE,
    CHANNEL_QUEUE_MAX, CHANNEL_IDLE_CLOSE_SECONDS, TLS_VERIFY,
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
        self._killed = False
        self.peers = []
        # Load or create persistent node ECDH keypair for onion layer
        self.priv_key, self.pub_pem = ecc_load_or_create_keypair(NODE_KEY_PATH)

        # Hidden-service relay state. A node may serve two distinct roles
        # for different sessions:
        #   - Intro point: receives hs_establish from a host, later relays
        #     hs_introduce from a client to that host. Never sees session data.
        #   - Rendezvous point: receives rv_establish with a cookie from a
        #     client, later matches a host's rv_join on the same cookie and
        #     splices hs_data frames between the two circuits.
        #
        # _hs_services:  service_addr -> host's intro-circuit request_id
        # _hs_pubs:      request_id -> pubkey of the endpoint on that circuit
        # _rv_cookies:   cookie -> client's rv request_id (pending join)
        # _rv_pairs:     req_id -> the paired side's req_id (after join)
        self._hs_services: dict[str, str] = {}
        self._hs_pubs: dict[str, str] = {}
        self._rv_cookies: dict[str, str] = {}
        self._rv_pairs: dict[str, str] = {}
        self._hs_lock = threading.Lock()

        # Reverse-channel registry: request_id -> send_back callable
        # When a tunnel CONNECT arrives on an inbound connection, we record
        # the send_back function (TCP socket writer or WS reverse_send) so
        # that later reverse_data / reverse_close frames can flow back
        # toward the proxy on the *same* connection — no new inbound connect.
        self._reverse_channels = {}
        self._reverse_lock = threading.Lock()

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Own WSClient for outbound WebSocket connections.
        # Each role (proxy/node) owns a separate WSClient so that reverse
        # frames arriving on this role's outbound connections are handled
        # by this role's handler - never intercepted by another role's.
        def _ws_reverse_handler(message):
            try:
                frame = json.loads(message) if isinstance(message, str) else message
                if frame.get('type') in ('reverse_data', 'reverse_close'):
                    self._handle_reverse_frame(frame)
            except Exception as e:
                log.error("WS reverse frame error: %s", e)

        self.ws_client = WSClient(
            self.priv_key, self.pub_pem,
            queue_max=CHANNEL_QUEUE_MAX,
            idle_close_seconds=CHANNEL_IDLE_CLOSE_SECONDS,
            tls_verify=TLS_VERIFY,
            on_receive=_ws_reverse_handler,
        )

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

        decrypted_message = onion_decrypt_checked(self.priv_key, encrypted_data)
        if decrypted_message is None:
            log.warning("Onion decryption failed; dropping frame")
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

        # Hidden-service envelope — same route/request_id shape as tunnels,
        # terminates at this node (intro or rendezvous point) instead of
        # opening TCP.
        HS_FRAME_TYPES = (
            'hs_establish', 'hs_introduce',
            'rv_establish', 'rv_join',
            'hs_data', 'hs_close',
        )
        if isinstance(layer, dict) and layer.get('type') in HS_FRAME_TYPES and isinstance(layer.get('route'), list):
            self._process_hs_frame(layer, send_back)
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

        log.warning("Unrecognized frame shape; dropping")

    def _process_hs_frame(self, layer: dict, send_back):
        """Process a hidden-service frame: forward if route non-empty, else
        terminate here as intro point or rendezvous point."""
        route = layer['route']
        typ = layer['type']
        req_id = layer.get('request_id', '')

        # Store inbound reverse channel on any circuit-opening frame.
        if typ in ('hs_establish', 'rv_establish', 'rv_join') and send_back and req_id:
            with self._reverse_lock:
                self._reverse_channels[req_id] = send_back

        if route:
            next_hop = route.pop(0)
            self.router.forward_message(next_hop, layer)
            return

        # Terminal dispatch.
        if typ == 'hs_establish':
            self._hs_terminal_establish(layer)
        elif typ == 'hs_introduce':
            self._hs_terminal_introduce(layer)
        elif typ == 'rv_establish':
            self._rv_terminal_establish(layer)
        elif typ == 'rv_join':
            self._rv_terminal_join(layer)
        elif typ == 'hs_data':
            self._rv_terminal_data(layer)
        elif typ == 'hs_close':
            self._rv_terminal_close(layer)

    def _hs_send_reverse(self, target_request_id: str, inner: dict) -> bool:
        """Send an inner payload back along the reverse channel of a circuit.

        Mirrors the exit-node reverse flow: encrypt the inner JSON for the
        endpoint's public key, wrap as a reverse_data frame, write via the
        stored send_back.  Intermediate hops forward the frame unchanged.
        """
        with self._reverse_lock:
            send_fn = self._reverse_channels.get(target_request_id)
        pub = self._hs_pubs.get(target_request_id)
        if not send_fn or not pub:
            log.warning("No reverse path for hs request_id=%s", target_request_id)
            return False
        encrypted = onion_encrypt_for_peer(pub, json.dumps(inner))
        frame = {
            'type': 'reverse_close' if inner.get('type') == 'hs_close' else 'reverse_data',
            'request_id': target_request_id,
            'encrypted_response': encrypted,
        }
        try:
            send_fn(json.dumps(frame))
            return True
        except Exception as e:
            log.error("hs reverse send error | %s", e)
            return False

    def _hs_terminal_establish(self, layer: dict):
        """Intro point: remember the host's circuit so we can relay introduces."""
        service_addr = layer.get('service_addr')
        host_pub = layer.get('pub')
        req_id = layer.get('request_id', '')
        if not service_addr or not host_pub or not req_id:
            log.warning("Malformed hs_establish; dropping")
            return
        with self._hs_lock:
            self._hs_services[service_addr] = req_id
            self._hs_pubs[req_id] = host_pub
        log.info("HS intro registered: %s (req=%s)", service_addr, req_id)

    def _hs_terminal_introduce(self, layer: dict):
        """Intro point: relay the client's introduce blob to the host.

        The introduce_payload is sealed to the service pubkey — this node
        cannot read it. We forward it along the host's intro circuit as
        reverse_data so the host can decrypt and react.
        """
        service_addr = layer.get('service_addr')
        blob = layer.get('introduce_payload')
        client_req = layer.get('request_id', '')
        if not service_addr or not blob:
            log.warning("Malformed hs_introduce; dropping")
            return
        with self._hs_lock:
            host_req = self._hs_services.get(service_addr)
        if not host_req:
            log.info("Introduce for unknown service %s; dropping", service_addr)
            return
        self._hs_send_reverse(host_req, {
            'type': 'hs_introduce',
            'service_addr': service_addr,
            'introduce_payload': blob,
        })
        # Acknowledge to the client along its intro circuit. The client
        # only learns that the introduce was delivered, nothing else.
        if client_req:
            # We may not have the client's pub stored — introduce circuits
            # aren't used for data, so best-effort only.
            pass
        log.info("Relayed hs_introduce for %s to host (host_req=%s)", service_addr, host_req)

    # ── Rendezvous-point role ──────────────────────────────────────

    def _rv_terminal_establish(self, layer: dict):
        """Rendezvous point: stash the cookie → client mapping for a later join."""
        cookie = layer.get('cookie')
        client_req = layer.get('request_id', '')
        client_pub = layer.get('pub')
        if not cookie or not client_req or not client_pub:
            log.warning("Malformed rv_establish; dropping")
            return
        with self._hs_lock:
            self._rv_cookies[cookie] = client_req
            self._hs_pubs[client_req] = client_pub
        log.info("RV established: cookie=%s… client_req=%s",
                 cookie[:8], client_req)

    def _rv_terminal_join(self, layer: dict):
        """Rendezvous point: match the cookie and splice the two circuits."""
        cookie = layer.get('cookie')
        host_req = layer.get('request_id', '')
        host_pub = layer.get('pub')
        if not cookie or not host_req or not host_pub:
            log.warning("Malformed rv_join; dropping")
            return
        with self._hs_lock:
            client_req = self._rv_cookies.pop(cookie, None)
            if not client_req:
                log.info("rv_join for unknown/expired cookie; dropping")
                return
            self._rv_pairs[client_req] = host_req
            self._rv_pairs[host_req] = client_req
            self._hs_pubs[host_req] = host_pub
        # Tell both sides the splice is live.
        self._hs_send_reverse(client_req, {
            'type': 'rv_ready',
            'request_id': client_req,
        })
        self._hs_send_reverse(host_req, {
            'type': 'rv_ready',
            'request_id': host_req,
        })
        log.info("RV spliced: client=%s host=%s", client_req, host_req)

    def _rv_terminal_data(self, layer: dict):
        """Rendezvous point: forward an hs_data chunk to the paired circuit."""
        req_id = layer.get('request_id', '')
        chunk = layer.get('chunk')
        if not req_id or chunk is None:
            return
        with self._hs_lock:
            other = self._rv_pairs.get(req_id)
        if not other:
            log.warning("hs_data with no paired circuit (req=%s)", req_id)
            return
        self._hs_send_reverse(other, {
            'type': 'hs_data',
            'request_id': other,
            'chunk': chunk,
        })

    def _rv_terminal_close(self, layer: dict):
        req_id = layer.get('request_id', '')
        if not req_id:
            return
        with self._hs_lock:
            other = self._rv_pairs.pop(req_id, None)
            if other:
                self._rv_pairs.pop(other, None)
        if other:
            self._hs_send_reverse(other, {
                'type': 'hs_close',
                'request_id': other,
            })

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

    def _shutdown(self, reason: str):
        """Shutdown callback for kill switch activation."""
        log.warning(f"Kill switch activated: {reason}")
        self._killed = True
        self.running = False
        try:
            self.server_socket.close()
        except Exception:
            pass
        sys.exit(0)

    def run(self):
        """Start the node server in a separate daemon thread."""
        server_thread = threading.Thread(target=self.start_server, daemon=True)
        server_thread.start()

        # Start kill switch monitor
        start_kill_switch_monitor(self._shutdown)

if __name__ == "__main__":
    node = ObscuraNode(port=5001)
    node.run()

    # Allow discovery to happen continuously
    while True:
        time.sleep(1)
