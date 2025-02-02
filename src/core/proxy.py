import socket
import threading
import random
import json
import time
import signal
import sys

# Import the discovery-based client
from src.client.obscura_client import ObscuraClient
# Import the top-level function that sends data through the onion route
from src.core.router import direct_relay_message

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9050  # SOCKS5 proxy port

# Global flag to stop all threads safely
running = True

# Create and start ObscuraClient for dynamic peer discovery
obscura_client = ObscuraClient()

def handle_browser_request(client_socket):
    """Handles incoming traffic from browsers and routes it through Obscura47."""
    global running
    try:
        if not running:
            return

        request = client_socket.recv(4096)
        if not request:
            return

        print(f"🌍 Received browser request (first 100 chars): {request[:100]}...")

        # Use the dynamically discovered peers
        peers = obscura_client.peers
        if not peers:
            print("⚠️ No discovered peers yet. Cannot route request.")
            client_socket.close()
            return

        # Pick a random peer from discovered peers
        next_hop = random.choice(peers)

        # Prepare a request packet with a response channel
        response_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response_socket.bind(("127.0.0.1", 0))  # Bind to an available random port
        response_port = response_socket.getsockname()[1]  # Get assigned port
        response_socket.listen(1)

        request_data = {
            "data": request.decode(),  # Send the full request
            "return_host": "127.0.0.1",
            "return_port": response_port,  # Tell exit node where to send response
        }

        # Relay the request through Obscura47
        direct_relay_message(json.dumps(request_data), next_hop, peers)

        print("⏳ Waiting for response from the exit node...")

        # Accept the response connection
        conn, _ = response_socket.accept()
        response = conn.recv(4096)

        # Send the response back to the browser
        client_socket.send(response)
        print(f"📤 Response relayed back to browser.")

    except Exception as e:
        if running:
            print(f"❌ Error in handle_browser_request: {e}")
    finally:
        client_socket.close()


def start_proxy():
    """Starts the local SOCKS5 proxy for Obscura47 and handles clean shutdown."""
    global running

    # Graceful exit handler
    def shutdown_handler(signum, frame):
        global running
        print("\n⚠️  Received shutdown signal. Stopping proxy...")
        running = False
        server.close()  # Close the server socket
        time.sleep(1)  # Allow clean shutdown
        sys.exit(0)

    # Attach signal handler for CTRL+C
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)  # Handle `kill` command too

    # Start peer discovery
    threading.Thread(target=obscura_client.start, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(5)
        server.settimeout(1)  # Prevent infinite blocking

        print(f"🚀 Obscura47 Proxy running on {PROXY_HOST}:{PROXY_PORT}")

        while running:
            try:
                client_socket, _ = server.accept()
                if not running:
                    break
                threading.Thread(
                    target=handle_browser_request,
                    args=(client_socket,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue  # Timeout lets us check `running` flag

    print("✅ Proxy shut down cleanly.")


if __name__ == "__main__":
    start_proxy()
