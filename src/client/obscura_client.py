import socket
import threading
import json
import time
from src.core.router import Router, decrypt_message
from src.core.discover import (
    listen_for_discovery,
    broadcast_discovery,
    NODE_MULTICAST_PORT
)

class ObscuraNode:
    def __init__(self, host='0.0.0.0', port=5001):
        """
        Initialize a relay node that listens for encrypted messages on TCP `port`.
        Also do discovery on the multicast port 50001.
        """
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True
        self.peers = []

        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 1) Listen for discovery on 50001, advertising that we have TCP port=port
        threading.Thread(
            target=listen_for_discovery,
            args=(self.peers, self.port, NODE_MULTICAST_PORT),
            daemon=True
        ).start()
        print(f"🚀 Node Discovery started on multicast port {NODE_MULTICAST_PORT}...")

        # 2) Send discovery requests on 50001
        for _ in range(3):
            broadcast_discovery(NODE_MULTICAST_PORT)
            time.sleep(2)

        print(f"⏳ Waiting for peers to be discovered...")
        time.sleep(5)  # Let some responses come in

        # 3) Create the router with discovered peers
        self.router = Router(self, self.peers)

    def start_server(self):
        """Start the node server to listen for incoming encrypted messages."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"🔹 Node started at {self.host}:{self.port}, waiting for connections...")
        except OSError as e:
            print(f"❌ Port {self.port} is already in use! Trying the next one...")
            self.port += 1
            self.start_server()
            return

        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"🔗 Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
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

                incoming_packet = json.loads(data)
                encrypted_data = incoming_packet.get("encrypted_data")
                if not encrypted_data:
                    print("⚠️ No encrypted data found. Dropping message.")
                    return

                # Decrypt
                decrypted_message = decrypt_message(encrypted_data)
                if decrypted_message is None:
                    print("⚠️ Decryption failed. Dropping message.")
                    return

                message_content = json.loads(decrypted_message)
                print(f"📩 Received at {self.host}:{self.port}: {message_content}")

                # Route next hop if any
                if message_content["route"]:
                    next_hop = message_content["route"].pop(0)
                    print(f"🔁 Forwarding to {next_hop['host']}:{next_hop['port']}")
                    self.router.forward_message(next_hop, message_content)
                else:
                    # We are final
                    print(f"✅ Final destination reached at {self.host}:{self.port}")
                    print(f"📜 Message: {message_content['data']}")

        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()

    def run(self):
        """Start the node server in a separate thread."""
        server_thread = threading.Thread(target=self.start_server, daemon=True)
        server_thread.start()


if __name__ == "__main__":
    node = ObscuraNode(port=5001)
    node.run()

    # After some time, try a test message
    time.sleep(5)
    if node.peers:
        destination = node.peers[0]
        node.router.relay_message("Hello, Obscura47!", destination)
    else:
        print("⚠️ No peers discovered yet!")
