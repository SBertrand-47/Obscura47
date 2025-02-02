import socket
import threading
import json
import time
from src.core.router import Router, decrypt_message
from src.client.obscura_client import ObscuraClient  # Import discovery
from src.core.discover import listen_for_discovery, broadcast_discovery  # Use correct discovery

NODE_DISCOVERY_PORT = 50001  # Separate multicast port for nodes

class ObscuraNode:
    def __init__(self, host='0.0.0.0', port=5001, enable_discovery=True):
        """
        Initialize a relay node that listens for encrypted messages.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

        # Fix: Set SO_REUSEADDR to prevent "Address already in use" errors
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Start peer discovery if enabled
        self.peers = []
        if enable_discovery:
            threading.Thread(target=listen_for_discovery, args=(self.peers, NODE_DISCOVERY_PORT), daemon=True).start()
            print(f"🚀 Node Discovery started on port {NODE_DISCOVERY_PORT}...")

            # Send discovery requests
            for _ in range(3):  # Try 3 times
                broadcast_discovery(NODE_DISCOVERY_PORT)
                time.sleep(2)

            print(f"⏳ Waiting for peers to be discovered...")
            time.sleep(5)  # Give time for discovery to populate peers

        # Create the router with updated peers
        self.router = Router(self, self.peers)

    def start_server(self):
        """Start the node server to listen for incoming encrypted messages."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"🔹 Node started at {self.host}:{self.port}, waiting for connections...")
        except OSError as e:
            print(f"❌ Port {self.port} is already in use! Trying another port...")
            self.port += 1  # Try the next available port
            self.start_server()  # Retry with new port
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
            while True:
                data = client_socket.recv(4096).decode()
                if not data:
                    break

                # Parse the JSON packet
                incoming_packet = json.loads(data)
                encrypted_data = incoming_packet.get("encrypted_data", None)
                if not encrypted_data:
                    print("⚠️ No encrypted data found. Dropping message.")
                    return

                # Decrypt the payload
                decrypted_message = decrypt_message(encrypted_data)
                if decrypted_message is None:
                    print("⚠️ Decryption failed. Dropping message.")
                    return

                message_content = json.loads(decrypted_message)
                print(f"📩 Received at {self.host}:{self.port}: {message_content}")

                # If there are more nodes in the route, pop the next hop and forward
                if message_content["route"]:
                    next_hop = message_content["route"].pop(0)
                    print(f"🔁 Forwarding to {next_hop['host']}:{next_hop['port']}")
                    self.router.forward_message(next_hop, message_content)
                else:
                    print(f"✅ Final destination reached at {self.host}:{self.port}")
                    print(f"📜 Message: {message_content['data']}")

        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()

    def run(self):
        """Start the node server in a separate thread."""
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()

# Start the node
if __name__ == "__main__":
    node = ObscuraNode(port=5001, enable_discovery=True)
    node.run()

    # Allow some time for discovery
    time.sleep(5)

    # Relay a test message through the network
    if node.peers:
        destination = node.peers[0]  # Pick first discovered peer
        node.router.relay_message("Hello, Obscura47!", destination)
    else:
        print("⚠️ No peers discovered yet!")
