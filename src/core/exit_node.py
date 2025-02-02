import socket
import json
import requests
import threading
import time
from src.core.router import decrypt_message, encrypt_message
from src.core.discover import broadcast_discovery, listen_for_discovery

EXIT_NODE_MULTICAST_PORT = 50003  # Discovery port for exit nodes
DISCOVERY_INTERVAL = 5  # Broadcast every 5 seconds

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

        # Start peer discovery
        threading.Thread(target=self.listen_for_proxies, daemon=True).start()
        threading.Thread(target=self.continuous_discovery, daemon=True).start()

    def listen_for_proxies(self):
        """Continuously listen for proxy/node discovery requests."""
        print(f"👂 Listening for discovery on port {EXIT_NODE_MULTICAST_PORT}...")
        listen_for_discovery(self.peers, self.port, EXIT_NODE_MULTICAST_PORT)

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
            data = client_socket.recv(4096).decode()
            if not data:
                return

            packet = json.loads(data)
            encrypted_data = packet.get("encrypted_data")
            if not encrypted_data:
                print("⚠️ No encrypted data found in request.")
                return

            # Decrypt the request (should contain 'data' and 'return_path')
            decrypted_message = decrypt_message(encrypted_data)
            if decrypted_message is None:
                print("⚠️ Failed to decrypt incoming exit request.")
                return

            request_data = json.loads(decrypted_message)
            print(f"🌍 Received Exit Request: {request_data}")

            url = request_data.get("data")
            return_path = request_data.get("return_path")  # Where to send response

            if not url:
                print("⚠️ No URL found in request_data.")
                return

            response_content = self.fetch_page(url)

            # Send response back to the proxy via return path
            self.send_response_back(return_path, response_content)

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
            resp = requests.get(url, headers=headers, timeout=5)
            return resp.text
        except Exception as e:
            print(f"❌ Error fetching page: {e}")
            return f"Error fetching {url}: {e}"

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

if __name__ == "__main__":
    exit_node = ExitNode(port=6000)
    exit_node.start_server()
