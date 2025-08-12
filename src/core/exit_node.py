import socket
import json
import requests
import ipaddress
import threading
import time
import base64
from src.core.encryptions import decrypt_message, encrypt_message, onion_decrypt_with_priv, ecc_load_or_create_keypair
from src.core.discover import broadcast_discovery, listen_for_discovery
from src.utils.config import EXIT_NODE_MULTICAST_PORT as CFG_EXIT_NODE_MULTICAST_PORT, DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL, EXIT_DOH_ENDPOINT, EXIT_DOH_TIMEOUT, EXIT_DENY_PRIVATE_IPS, EXIT_ALLOW_DOMAINS, EXIT_DENY_DOMAINS, EXIT_KEY_PATH

EXIT_NODE_MULTICAST_PORT = CFG_EXIT_NODE_MULTICAST_PORT  # Discovery port for exit nodes
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL  # Broadcast interval

class ExitNode:
    def __init__(self, host='0.0.0.0', port=6000):
        """The ExitNode listens for final relay messages, fetches external URLs,
        and sends the response back through the route.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.peers = []  # Stores discovered nodes
        self.tunnels = {}  # request_id -> { 'sock': socket, 'return_path': dict }
        self.priv_key, self.pub_pem = ecc_load_or_create_keypair(EXIT_KEY_PATH)

        # Start peer discovery
        threading.Thread(target=self.listen_for_proxies, daemon=True).start()
        threading.Thread(target=self.continuous_discovery, daemon=True).start()

    def listen_for_proxies(self):
        """Continuously listen for proxy/node discovery requests."""
        print(f"👂 Listening for discovery on port {EXIT_NODE_MULTICAST_PORT}...")
        listen_for_discovery(self.peers, self.port, EXIT_NODE_MULTICAST_PORT, extra_fields={'pub': self.pub_pem})

    def continuous_discovery(self):
        """Continuously broadcasts discovery requests so proxies/nodes can find the Exit Node."""
        while self.running:
            print("🔍 Broadcasting Exit Node discovery request...")
            broadcast_discovery(EXIT_NODE_MULTICAST_PORT)
            time.sleep(DISCOVERY_INTERVAL)

    def start_server(self):
        """Start listening for incoming relay requests."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"🚪 Exit Node started at {self.host}:{self.port}, waiting for requests...")

        while self.running:
            client_socket, addr = self.server_socket.accept()
            print(f"🔗 Connection from {addr}")
            threading.Thread(target=self.handle_request, args=(client_socket,)).start()

    def handle_request(self, client_socket):
        """Handle requests forwarded through the network."""
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
                    encrypted_data = packet.get("encrypted_data")
                    if not encrypted_data:
                        continue
                    # Try onion layer first
                    decrypted_message = onion_decrypt_with_priv(self.priv_key, encrypted_data)
                    if decrypted_message is None:
                        decrypted_message = decrypt_message(encrypted_data)
                    if decrypted_message is None:
                        continue
                    request_data = json.loads(decrypted_message)
                    req_id = request_data.get("request_id", "")
                    msg_type = request_data.get("type")
                    if msg_type == "connect":
                        # Initialize outbound TCP to target
                        host = request_data.get("host")
                        port = int(request_data.get("port", 443))
                        return_path = request_data.get("return_path")
                        threading.Thread(target=self._serve_connect, args=(host, port, return_path, req_id), daemon=True).start()
                        print(f"🔌 Exit CONNECT init to {host}:{port} | request_id={req_id}")
                    elif msg_type == "data":
                        # Data for an existing tunnel
                        chunk_b64 = request_data.get("chunk")
                        if not chunk_b64:
                            continue
                        info = self.tunnels.get(req_id)
                        if not info:
                            continue
                        try:
                            info['sock'].sendall(base64.b64decode(chunk_b64))
                        except Exception as e:
                            print(f"❌ Exit write error | request_id={req_id} | {e}")
                    elif msg_type == "close":
                        info = self.tunnels.pop(req_id, None)
                        if info:
                            try:
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

        except Exception as e:
            print(f"❌ Error in Exit Node: {e}")
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
            print(f"❌ Error fetching page: {e}")
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
        if EXIT_ALLOW_DOMAINS and not any(host.endswith(d) for d in EXIT_ALLOW_DOMAINS):
            return False
        if EXIT_DENY_DOMAINS and any(host.endswith(d) for d in EXIT_DENY_DOMAINS):
            return False
        return True

    def send_response_back(self, return_path, response_data):
        """Sends the fetched response **directly back** to the proxy."""
        if not return_path or "host" not in return_path or "port" not in return_path:
            print("⚠️ Invalid return path provided, response lost.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((return_path['host'], return_path['port']))  # Corrected proxy port handling
                packet = {
                    "request_id": return_path.get("request_id", ""),
                    "data": response_data
                }
                sock.send(json.dumps(packet).encode())
                print(f"📤 Sent response back to proxy.")
        except Exception as e:
            print(f"❌ Error sending response to proxy: {e}")

    def send_stream_chunk(self, return_path, request_id: str, data_bytes: bytes):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((return_path['host'], return_path['port']))
                packet = {
                    "type": "data",
                    "request_id": request_id,
                    "chunk": base64.b64encode(data_bytes).decode(),
                }
                sock.send(json.dumps(packet).encode())
        except Exception as e:
            print(f"❌ Error sending stream chunk: {e}")

    def send_stream_close(self, return_path, request_id: str):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((return_path['host'], return_path['port']))
                packet = {
                    "type": "close",
                    "request_id": request_id,
                }
                sock.send(json.dumps(packet).encode())
        except Exception as e:
            print(f"❌ Error sending stream close: {e}")

    def _serve_connect(self, host: str, port: int, return_path: dict, request_id: str):
        try:
            out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            out.connect((host, port))
            self.tunnels[request_id] = { 'sock': out, 'return_path': return_path }

            # Start reader thread: pump origin->proxy
            def reader():
                try:
                    while True:
                        data = out.recv(8192)
                        if not data:
                            break
                        self.send_stream_chunk(return_path, request_id, data)
                except Exception as e:
                    print(f"❌ Exit reader error | request_id={request_id} | {e}")
                finally:
                    self.send_stream_close(return_path, request_id)
                    try:
                        out.close()
                    except Exception:
                        pass
                    self.tunnels.pop(request_id, None)

            threading.Thread(target=reader, daemon=True).start()
        except Exception as e:
            print(f"❌ CONNECT error to {host}:{port} | {e}")

if __name__ == "__main__":
    exit_node = ExitNode(port=6000)
    exit_node.start_server()
