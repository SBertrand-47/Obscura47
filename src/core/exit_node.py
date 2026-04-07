import socket
import json
import requests
import ipaddress
import threading
import time
import base64
from src.utils.logger import get_logger
from src.core.encryptions import decrypt_message, encrypt_message, onion_decrypt_with_priv, onion_decrypt_checked, ecc_load_or_create_keypair, onion_encrypt_for_peer
from src.core.discover import broadcast_discovery, listen_for_discovery
from src.core.internet_discovery import start_heartbeat
from src.core.ws_transport import WSServer, get_ws_client
from src.core.router import _send_frame_via_route
from src.utils.config import (
    EXIT_NODE_MULTICAST_PORT as CFG_EXIT_NODE_MULTICAST_PORT,
    DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL,
    EXIT_DOH_ENDPOINT, EXIT_DOH_TIMEOUT, EXIT_DENY_PRIVATE_IPS,
    EXIT_ALLOW_DOMAINS, EXIT_DENY_DOMAINS, EXIT_KEY_PATH, EXIT_WS_PORT,
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
        # Try onion layer first
        decrypted_message = onion_decrypt_checked(self.priv_key, encrypted_data)
        if decrypted_message is None:
            decrypted_message = decrypt_message(encrypted_data)
        if decrypted_message is None:
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
            # Backward-compatible: treat 'data' field as URL fetch request
            try:
                url = request_data.get("data")
                return_path = request_data.get("return_path")
                if isinstance(url, str) and return_path:
                    body = self.fetch_page(url)
                    self.send_response_back(return_path, body)
            except Exception:
                pass

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

    def start_server(self):
        """Start listening for incoming relay requests (legacy TCP)."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)
        log.info(f"Exit Node started at {self.host}:{self.port} (TCP), waiting for requests...")

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

    def fetch_page(self, url):
        """Fetch an external page while stripping metadata."""
        try:
            headers = {
                "User-Agent": "Obscura47-Exit-Node",
                "Referer": "",
                "X-Forwarded-For": "",
            }
            # DoH resolution
            host = self._extract_host(url)
            if not self._domain_allowed(host):
                return "Domain not allowed"
            ip_list = self._resolve_doh(host)
            if not ip_list:
                return "Unable to resolve host"
            # Choose first IP and connect using it, preserve Host header
            target_ip = ip_list[0]
            if EXIT_DENY_PRIVATE_IPS and self._is_private_ip(target_ip):
                return "Blocked private/bogon IP"
            resp = requests.get(url, headers={**headers, 'Host': host}, timeout=5)
            return resp.text
        except Exception as e:
            log.error(f"Error fetching page: {e}")
            return f"Error fetching {url}: {e}"

    def _extract_host(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    def _resolve_doh(self, host: str):
        try:
            ips = []
            for rrtype, typcode in (("A", 1), ("AAAA", 28)):
                params = {"name": host, "type": rrtype}
                r = requests.get(EXIT_DOH_ENDPOINT, params=params, headers={'accept': 'application/dns-json'}, timeout=EXIT_DOH_TIMEOUT)
                if r.ok:
                    data = r.json()
                    for ans in data.get('Answer', []) or []:
                        if ans.get('type') == typcode and ans.get('data'):
                            ips.append(ans['data'])
            return ips
        except Exception:
            return []

    def _is_private_ip(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return True

    def _domain_allowed(self, host: str) -> bool:
        def _matches(host: str, pattern: str) -> bool:
            """Match domain or subdomain: 'example.com' matches 'example.com' and 'sub.example.com'."""
            return host == pattern or host.endswith("." + pattern)

        if EXIT_ALLOW_DOMAINS and not any(_matches(host, d) for d in EXIT_ALLOW_DOMAINS):
            return False
        if EXIT_DENY_DOMAINS and any(_matches(host, d) for d in EXIT_DENY_DOMAINS):
            return False
        return True

    def _send_to_proxy(self, return_path: dict, packet: dict):
        """Send a response packet back to the proxy.

        Preferred path: **reverse channel** — the response is encrypted for
        the proxy's public key and sent back through the same inbound
        connection that delivered the original CONNECT frame.  Each relay
        hop forwards it back on *its* stored reverse channel, so no new
        inbound connections are required.  This works even when the proxy
        is behind NAT.

        Fallback: relay-route / direct WS / direct TCP (legacy behaviour).
        """
        req_id = packet.get('request_id', '')

        # ── 1. Reverse channel (NAT-safe) ────────────────────────
        info = self.tunnels.get(req_id)
        send_back = info.get('send_back') if info else None
        if send_back:
            try:
                proxy_pub = return_path.get('pub')
                inner_json = json.dumps(packet)
                encrypted = onion_encrypt_for_peer(proxy_pub, inner_json) if proxy_pub else inner_json
                pkt_type = packet.get('type', '')
                reverse_type = 'reverse_close' if pkt_type == 'close' else 'reverse_data'
                reverse_frame = {
                    'type': reverse_type,
                    'request_id': req_id,
                    'encrypted_response': encrypted,
                }
                send_back(json.dumps(reverse_frame))
                return
            except Exception as e:
                log.warning(f"Reverse channel failed for {req_id}, falling back: {e}")

        # ── 2. Relay-route fallback ───────────────────────────────
        packet_json = json.dumps(packet)
        return_route = return_path.get("return_route")
        if return_route and isinstance(return_route, list) and len(return_route) > 0:
            proxy_hop = {"host": return_path["host"], "port": return_path["port"]}
            if return_path.get("pub"):
                proxy_hop["pub"] = return_path["pub"]
            remaining = list(return_route[1:]) + [proxy_hop]
            envelope = dict(packet)
            envelope["route"] = remaining
            _send_frame_via_route([return_route[0]], envelope)
            return

        # ── 3. Direct WS ─────────────────────────────────────────
        ws_port = return_path.get("ws_port")
        if ws_port:
            client = get_ws_client()
            if client and client.send_frame(return_path['host'], ws_port, packet_json):
                return

        # ── 4. Direct TCP (only works if proxy is reachable) ─────
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect((return_path['host'], return_path['port']))
                sock.send((packet_json + "\n").encode())
        except Exception as e:
            log.error(f"Error sending to proxy: {e}")

    def send_response_back(self, return_path, response_data):
        """Sends the fetched response back to the proxy."""
        if not return_path or "host" not in return_path or "port" not in return_path:
            log.warning("Invalid return path provided, response lost.")
            return
        packet = {
            "request_id": return_path.get("request_id", ""),
            "data": response_data
        }
        self._send_to_proxy(return_path, packet)
        log.info("Sent response back to proxy.")

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
