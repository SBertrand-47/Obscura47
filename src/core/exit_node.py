import socket
import json
import threading
import time
import base64
import sys
from src.utils.logger import get_logger
from src.core.encryptions import onion_decrypt_checked, ecc_load_or_create_keypair, onion_encrypt_for_peer
from src.core.discover import broadcast_discovery, listen_for_discovery
from src.core.internet_discovery import start_heartbeat, start_kill_switch_monitor
from src.core.ws_transport import WSServer, get_ws_client
from src.utils.config import (
    EXIT_NODE_MULTICAST_PORT as CFG_EXIT_NODE_MULTICAST_PORT,
    DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL,
    EXIT_KEY_PATH, EXIT_WS_PORT,
    WS_TLS_CERT, WS_TLS_KEY, WS_TLS_ACTIVE, TUNNEL_IDLE_SECONDS,
)

EXIT_NODE_MULTICAST_PORT = CFG_EXIT_NODE_MULTICAST_PORT  # Discovery port for exit nodes
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL  # Broadcast interval

log = get_logger(__name__)

class ExitNode:
    def __init__(self, host='0.0.0.0', port=6000):
        """The ExitNode listens for final relay messages, fetches external URLs,
        and sends the response back through the route.
        """
        self.host = host
        self.port = port
        self.ws_port = EXIT_WS_PORT
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self._killed = False
        self.peers = []  # Stores discovered nodes
        self.tunnels = {}  # request_id -> { 'sock': socket, 'return_path': dict }
        self.priv_key, self.pub_pem = ecc_load_or_create_keypair(EXIT_KEY_PATH)

        # Initialize global WS client for outbound WebSocket connections
        get_ws_client(self.priv_key, self.pub_pem)

        # Start peer discovery
        threading.Thread(target=self.listen_for_proxies, daemon=True).start()
        threading.Thread(target=self.continuous_discovery, daemon=True).start()

        self.ws_tls_enabled = WS_TLS_ACTIVE

        # Register with internet bootstrap registry (with ws_port and priv_key for auth)
        start_heartbeat("exit", self.port, self.pub_pem,
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
        log.info(f"WebSocket server on port {self.ws_port}")

        # Periodic sweeper for abandoned tunnels
        threading.Thread(target=self._tunnel_sweeper, daemon=True).start()

    def _on_ws_frame(self, message: str, reverse_send=None):
        """Handle a frame received via WebSocket (same logic as TCP)."""
        try:
            packet = json.loads(message)
            self.process_frame(packet, send_back=reverse_send)
        except Exception as e:
            log.error(f"[ws] Frame error: {e}")

    def process_frame(self, packet: dict, send_back=None):
        """Process an incoming encrypted frame (shared by TCP and WebSocket handlers).

        ``send_back`` is an optional callable that writes data back to the
        inbound connection this frame arrived on — used as a reverse channel
        for streaming responses back through the relay chain.
        """
        encrypted_data = packet.get("encrypted_data")
        if not encrypted_data:
            return
        decrypted_message = onion_decrypt_checked(self.priv_key, encrypted_data)
        if decrypted_message is None:
            log.warning("Onion decryption failed; dropping frame")
            return
        request_data = json.loads(decrypted_message)
        # Onion routing wraps the final payload in {"payload": {...}} — unwrap
        if "payload" in request_data and isinstance(request_data["payload"], dict):
            request_data = request_data["payload"]
        req_id = request_data.get("request_id", "")
        msg_type = request_data.get("type")
        if msg_type == "connect":
            # Pre-register the tunnel with a write queue so data frames
            # arriving before the outbound TCP connect completes are buffered.
            host = request_data.get("host")
            port = int(request_data.get("port", 443))
            return_path = request_data.get("return_path")
            self.tunnels[req_id] = {
                'sock': None, 'return_path': return_path,
                'queue': [], 'ready': threading.Event(),
                'created': time.time(), 'last_active': time.time(),
                'send_back': send_back,  # reverse channel to relay chain
            }
            threading.Thread(target=self._serve_connect, args=(host, port, return_path, req_id), daemon=True).start()
            log.info(f"Exit CONNECT init to {host}:{port} | request_id={req_id}")
        elif msg_type == "data":
            chunk_b64 = request_data.get("chunk")
            if not chunk_b64:
                return
            info = self.tunnels.get(req_id)
            if not info:
                return
            raw = base64.b64decode(chunk_b64)
            if info.get('ready') and not info['ready'].is_set():
                # Outbound connect still in progress — buffer
                info.setdefault('queue', []).append(raw)
                return
            try:
                info['sock'].sendall(raw)
                info['last_active'] = time.time()
            except Exception as e:
                log.error(f"Exit write error | request_id={req_id} | {e}")
        elif msg_type == "close":
            info = self.tunnels.pop(req_id, None)
            if info:
                try:
                    if info.get('sock'):
                        info['sock'].close()
                except Exception:
                    pass
        else:
            log.warning(f"Unknown tunnel frame type: {msg_type} | request_id={req_id}")

    def listen_for_proxies(self):
        """Continuously listen for proxy/node discovery requests."""
        log.info(f"Listening for discovery on port {EXIT_NODE_MULTICAST_PORT}...")
        listen_for_discovery(self.peers, self.port, EXIT_NODE_MULTICAST_PORT, extra_fields={'pub': self.pub_pem})

    def continuous_discovery(self):
        """Continuously broadcasts discovery requests so proxies/nodes can find the Exit Node."""
        while self.running:
            log.info("Broadcasting Exit Node discovery request...")
            broadcast_discovery(EXIT_NODE_MULTICAST_PORT)
            time.sleep(DISCOVERY_INTERVAL)

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

    def start_server(self):
        """Start listening for incoming relay requests (legacy TCP)."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        log.info(f"Exit Node started at {self.host}:{self.port} (TCP), waiting for requests...")

        # Start kill switch monitor
        start_kill_switch_monitor(self._shutdown)

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                log.info(f"Connection from {addr}")
                threading.Thread(target=self.handle_request, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                log.info("Exit Node shutting down...")
                break

    def shutdown(self):
        """Gracefully stop the exit node and close all tunnels."""
        self.running = False
        try:
            self.server_socket.close()
        except Exception:
            pass
        for req_id, info in list(self.tunnels.items()):
            try:
                if info.get('sock'):
                    info['sock'].close()
            except Exception:
                pass
        self.tunnels.clear()
        if hasattr(self, 'ws_server'):
            try:
                self.ws_server.stop()
            except Exception:
                pass
        log.info(f"Exit Node {self.host}:{self.port} shut down.")

    def _tunnel_sweeper(self):
        """Close tunnels that have been idle too long."""
        while self.running:
            time.sleep(10)
            now = time.time()
            for req_id, info in list(self.tunnels.items()):
                last = info.get('last_active', info.get('created', 0))
                if now - last > TUNNEL_IDLE_SECONDS:
                    try:
                        if info.get('sock'):
                            info['sock'].close()
                    except Exception:
                        pass
                    self.tunnels.pop(req_id, None)
                    log.info(f"Swept idle tunnel {req_id}")

    def handle_request(self, client_socket):
        """Handle requests forwarded through the network (legacy TCP).

        Creates a thread-safe ``send_back`` closure so that reverse-channel
        response frames can be written back on this same inbound connection.
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
                    packet = json.loads(line)
                    self.process_frame(packet, send_back=_tcp_send_back)

        except Exception as e:
            log.error(f"Error in Exit Node: {e}")
        finally:
            client_socket.close()

    def _send_to_proxy(self, return_path: dict, packet: dict):
        """Send a response packet back to the proxy via reverse channel.

        The response is encrypted for the proxy's public key and sent back
        through the same inbound connection that delivered the original
        CONNECT frame.  Each relay hop forwards it back on *its* stored
        reverse channel, so no new inbound connections are required.
        """
        req_id = packet.get('request_id', '')
        info = self.tunnels.get(req_id)
        send_back = info.get('send_back') if info else None
        if not send_back:
            log.error(f"No reverse channel for {req_id}; response lost")
            return
        try:
            proxy_pub = return_path.get('pub')
            inner_json = json.dumps(packet)
            if not proxy_pub:
                log.error(f"No proxy public key for {req_id}; response lost")
                return
            encrypted = onion_encrypt_for_peer(proxy_pub, inner_json)
            pkt_type = packet.get('type', '')
            reverse_type = 'reverse_close' if pkt_type == 'close' else 'reverse_data'
            reverse_frame = {
                'type': reverse_type,
                'request_id': req_id,
                'encrypted_response': encrypted,
            }
            send_back(json.dumps(reverse_frame))
        except Exception as e:
            log.error(f"Reverse channel send failed for {req_id}: {e}")

    def send_stream_chunk(self, return_path, request_id: str, data_bytes: bytes):
        packet = {
            "type": "data",
            "request_id": request_id,
            "chunk": base64.b64encode(data_bytes).decode(),
        }
        self._send_to_proxy(return_path, packet)

    def send_stream_close(self, return_path, request_id: str):
        packet = {
            "type": "close",
            "request_id": request_id,
        }
        self._send_to_proxy(return_path, packet)

    def _serve_connect(self, host: str, port: int, return_path: dict, request_id: str):
        info = self.tunnels.get(request_id)
        try:
            out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out.connect((host, port))
            # Store the live socket and flush any queued data frames
            if info:
                info['sock'] = out
                for queued in info.pop('queue', []):
                    out.sendall(queued)
                info['ready'].set()
            else:
                self.tunnels[request_id] = {'sock': out, 'return_path': return_path}

            # Start reader thread: pump origin->proxy
            def reader():
                try:
                    while True:
                        data = out.recv(8192)
                        if not data:
                            break
                        self.send_stream_chunk(return_path, request_id, data)
                except Exception as e:
                    log.error(f"Exit reader error | request_id={request_id} | {e}")
                finally:
                    self.send_stream_close(return_path, request_id)
                    try:
                        out.close()
                    except Exception:
                        pass
                    self.tunnels.pop(request_id, None)

            threading.Thread(target=reader, daemon=True).start()
        except Exception as e:
            log.error(f"CONNECT error to {host}:{port} | {e}")
            self.tunnels.pop(request_id, None)

if __name__ == "__main__":
    exit_node = ExitNode(port=6000)
    exit_node.start_server()
