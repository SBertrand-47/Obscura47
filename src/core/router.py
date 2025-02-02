import random
import json
import socket
from Crypto.Cipher import AES
import base64
import os

# Generate a single AES key for demonstration.
# (In a real onion routing system, you'd have per-hop keys!)
AES_KEY = os.urandom(16)

def encrypt_message(message, key=AES_KEY):
    """
    Encrypts message using AES (CFB) with a unique IV.
    Returns a base64-encoded string containing IV + ciphertext.
    """
    iv = os.urandom(16)  # Generate a new IV for each message
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted = cipher.encrypt(message.encode())

    # Combine IV + encrypted data, then base64-encode
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(encrypted_message, key=AES_KEY):
    """
    Decrypts a base64-encoded string that contains IV + ciphertext.
    Returns the decrypted plaintext (str) or None if there's an error.
    """
    try:
        data = base64.b64decode(encrypted_message)
        iv = data[:16]  # IV is the first 16 bytes
        encrypted_data = data[16:]  # Remaining bytes are the ciphertext

        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(encrypted_data).decode()
        return decrypted
    except Exception as e:
        print(f"❌ Decryption error: {e}")
        return None

class Router:
    def __init__(self, node, peers):
        """
        Initializes the router with a node instance and a list of peers.
        `peers` is a list of dictionaries: [{host, port}, ...].
        """
        self.node = node
        self.peers = peers

    def build_random_route(self, hops=3):
        """
        Generates a random path of nodes for relaying messages.
        If there aren't enough peers, use as many as available.
        """
        if len(self.peers) < hops:
            print("⚠️ Not enough peers for full hop count!")
            hops = len(self.peers)
        return random.sample(self.peers, hops) if hops > 0 else []

    def relay_message(self, data, destination):
        """
        Encrypts the message with the final route included,
        then sends it to the first hop.
        
        :param data: The data to send (e.g., a URL).
        :param destination: The final node dict (e.g., exit node).
        """
        # Build a route through random peers and append the final (exit) node
        route = self.build_random_route()
        route.append(destination)  # The last hop

        # Create a JSON object with the data and entire route
        message = json.dumps({"data": data, "route": route})

        # Encrypt once for the first hop
        encrypted_message = encrypt_message(message)

        # Send the encrypted message to the first node in the route
        if route:
            first_hop = route[0]
            self.send_to_next_hop(first_hop, encrypted_message)
        else:
            print("⚠️ No peers/routes available. Message not sent.")

    def forward_message(self, next_node, message_content):
        """
        Re-encrypts the updated message_content (already a dict),
        then sends to the next hop in the route.
        """
        new_encrypted = encrypt_message(json.dumps(message_content))
        self.send_to_next_hop(next_node, new_encrypted)

    def send_to_next_hop(self, next_node, encrypted_message):
        """
        Sends an already-encrypted message to the next hop.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((next_node['host'], next_node['port']))
                # Wrap the encrypted data in JSON for transport
                packet = {"encrypted_data": encrypted_message}
                sock.send(json.dumps(packet).encode())
                print(f"📤 Sent encrypted message to {next_node['host']}:{next_node['port']}")
        except Exception as e:
            print(f"❌ Error sending to {next_node}: {e}")

def direct_relay_message(data, destination, peers):
    """
    A top-level helper for modules (like `proxy.py`) that just want
    to relay a message without manually instantiating a Router.
    """
    r = Router(node=None, peers=peers)
    r.relay_message(data, destination)
