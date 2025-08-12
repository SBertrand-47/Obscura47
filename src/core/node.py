import socket
import threading
import json
import time
from src.core.router import Router
from src.core.encryptions import decrypt_message, onion_decrypt_with_priv, ecc_load_or_create_keypair
from src.core.discover import listen_for_discovery, broadcast_discovery
from src.utils.config import NODE_MULTICAST_PORT as CFG_NODE_MULTICAST_PORT, DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL, ONION_ONLY, NODE_KEY_PATH

NODE_MULTICAST_PORT = CFG_NODE_MULTICAST_PORT  # Node discovery
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL  # Broadcast interval

class ObscuraNode:
    def __init__(self, host='0.0.0.0', port=5001):
        """
        Initialize a relay node that listens for encrypted messages.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.peers = []
        # Load or create persistent node ECDH keypair for onion layer
        self.priv_key, self.pub_pem = ecc_load_or_create_keypair(NODE_KEY_PATH)

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 🔥 Start discovery listener continuously
        threading.Thread(
            target=self.listen_for_nodes,
            daemon=True
        ).start()

        # 🔥 Continuously broadcast discovery requests
        threading.Thread(
            target=self.continuous_discovery,
            daemon=True
        ).start()

        print(f"🚀 Node Discovery started on port {NODE_MULTICAST_PORT}...")

        # Allow time for initial discovery
        time.sleep(5)

        # Create the router with updated peers
        self.router = Router(self, self.peers)

    def listen_for_nodes(self):
        """Continuously listen for other nodes' discovery responses."""
        print("👂 Listening for discovery on 50002...")
        listen_for_discovery(self.peers, self.port, NODE_MULTICAST_PORT, extra_fields={'pub': self.pub_pem})

    def continuous_discovery(self):
        """Continuously broadcast discovery requests every few seconds."""
        while self.running:
            print("🔍 Broadcasting discovery request...")
            broadcast_discovery(NODE_MULTICAST_PORT)
            time.sleep(DISCOVERY_INTERVAL)

    def start_server(self):
        """Start the node server to listen for incoming encrypted messages."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"🔹 Node started at {self.host}:{self.port}, waiting for connections...")
        except OSError:
            print(f"❌ Port {self.port} is already in use! Trying another port...")
            self.port += 1  
            self.start_server()  
            return

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"🔗 Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            except OSError:
                print("⚠️ Node shutting down...")
                break

    def handle_client(self, client_socket):
        """Handles incoming encrypted messages from other nodes."""
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
                encrypted_data = incoming_packet.get("encrypted_data", None)
                if not encrypted_data:
                    print("⚠️ No encrypted data found. Dropping message.")
                    return

                # Try onion layer first; fall back to legacy frame encryption
                decrypted_message = onion_decrypt_with_priv(self.priv_key, encrypted_data)
                if decrypted_message is not None:
                    try:
                        layer = json.loads(decrypted_message)
                        if 'payload' in layer:
                            # Final payload reached this hop
                            payload = layer['payload']
                            req_id = payload.get("request_id", "")
                            print(f"✅ Final destination reached at {self.host}:{self.port} | request_id={req_id}")
                            continue
                        next_hop = layer.get('next_hop')
                        inner = layer.get('inner')
                        if not next_hop or inner is None:
                            print("⚠️ Malformed onion layer; dropping")
                            return
                        if isinstance(next_hop, dict):
                            encrypted_inner = inner if isinstance(inner, str) else json.dumps(inner)
                            # Forward onion-encrypted inner to next hop (persist where applicable)
                            self.router.send_to_next_hop(next_hop, encrypted_inner)
                            continue
                        print("⚠️ Invalid next_hop format; dropping")
                        return
                    except Exception as e:
                        print(f"⚠️ Onion decode error: {e}")
                        return
                else:
                    if ONION_ONLY:
                        print("⚠️ Onion-only mode: legacy frame rejected")
                        return
                    decrypted_legacy = decrypt_message(encrypted_data)
                    if decrypted_legacy is None:
                        print("⚠️ Decryption failed. Dropping message.")
                        return
                    message_content = json.loads(decrypted_legacy)
                    hop_count = len(message_content.get("route", []))
                    req_id = message_content.get("request_id", "")
                    print(f"📩 Received at {self.host}:{self.port} | hops_remaining={hop_count} | request_id={req_id}")

                    # If there are more nodes in the route, pop the next hop and forward
                    if message_content["route"]:
                        next_hop = message_content["route"].pop(0)
                        print(f"🔁 Forwarding to {next_hop['host']}:{next_hop['port']} | request_id={req_id}")
                        self.router.forward_message(next_hop, message_content)
                    else:
                        print(f"✅ Final destination reached at {self.host}:{self.port} | request_id={req_id}")

        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()

    def run(self):
        """Start the node server in a separate thread."""
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()

if __name__ == "__main__":
    node = ObscuraNode(port=5001)
    node.run()

    # Allow discovery to happen continuously
    while True:
        time.sleep(1)
