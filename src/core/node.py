import socket
import threading
import json
from core.router import Router, decrypt_message

class ObscuraNode:
    def __init__(self, host='127.0.0.1', port=5000, peers=None):
        """
        :param host: The IP address for this node.
        :param port: The port for this node.
        :param peers: A list of dicts, e.g. [{"host": "...", "port": 1234}, ...].
        """
        self.host = host
        self.port = port
        self.peers = peers if peers else []  # Known peers
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = True

        # Create the router
        self.router = Router(self, self.peers)

    def start_server(self):
        """
        Start the node server to listen for incoming connections.
        """
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"🔹 Node started at {self.host}:{self.port}, waiting for connections...")

        while self.running:
            client_socket, addr = self.server_socket.accept()
            print(f"🔗 Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """Handles incoming encrypted messages from other nodes."""
        try:
            while True:
                data = client_socket.recv(4096).decode()
                if not data:
                    break

                # Parse the JSON packet for "encrypted_data"
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

                # Convert decrypted JSON string into a Python dict
                try:
                    message_content = json.loads(decrypted_message)
                except json.JSONDecodeError:
                    print("⚠️ Received corrupted or incorrectly decrypted message. Ignoring.")
                    return

                print(f"📩 Received at {self.host}:{self.port}: {message_content}")

                # If there are more nodes in the route, pop the next hop and forward
                if message_content["route"]:
                    next_hop = message_content["route"].pop(0)
                    print(f"🔁 Forwarding to {next_hop['host']}:{next_hop['port']}")
                    self.router.forward_message(next_hop, message_content)
                else:
                    # No more hops -> final destination
                    print(f"✅ Final destination reached at {self.host}:{self.port}")
                    print(f"📜 Message: {message_content['data']}")

        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()

    def run(self):
        """
        Start the node server in a separate thread.
        """
        server_thread = threading.Thread(target=self.start_server)
        server_thread.start()


if __name__ == "__main__":
    node = ObscuraNode(port=5001, peers=[{"host": "127.0.0.1", "port": 5002}])
    node.run()

    # Example: Send a multi-hop message (after short delay)
    import time
    time.sleep(2)
    node.router.relay_message(
        "Hello, Obscura47!",
        {"host": "127.0.0.1", "port": 5003}
    )
