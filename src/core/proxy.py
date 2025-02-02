import socket
import threading
import random
import json
import time
import signal
import sys

from src.client.obscura_client import ObscuraClient
from src.core.router import direct_relay_message

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9050

running = True
obscura_client = ObscuraClient()

def handle_browser_request(client_socket):
    global running
    try:
        if not running:
            return

        request = client_socket.recv(4096)
        if not request:
            return

        print(f"🌍 Received browser request (first 100 chars): {request[:100]}...")

        # Use discovered peers
        peers = obscura_client.peers
        if not peers:
            print("⚠️ No discovered peers yet. Cannot route request.")
            client_socket.close()
            return

        # Pick a random peer
        next_hop = random.choice(peers)

        # Set up a small "server" to accept the exit node's response
        response_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response_socket.bind(("127.0.0.1", 0))
        response_port = response_socket.getsockname()[1]
        response_socket.listen(1)

        request_data = {
            "data": request.decode(),
            "return_host": "127.0.0.1",
            "return_port": response_port,
        }

        # Relay the request through Obscura47
        direct_relay_message(json.dumps(request_data), next_hop, peers)
        print("⏳ Waiting for response from the exit node...")

        conn, _ = response_socket.accept()
        response = conn.recv(4096)

        # Send back to browser
        client_socket.send(response)
        print("📤 Response relayed back to browser.")

    except Exception as e:
        if running:
            print(f"❌ Error in handle_browser_request: {e}")
    finally:
        client_socket.close()

def start_proxy():
    global running

    def shutdown_handler(signum, frame):
        global running
        print("\n⚠️  Received shutdown signal. Stopping proxy...")
        running = False
        server.close()
        time.sleep(1)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    threading.Thread(target=obscura_client.start, daemon=True).start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(5)
        server.settimeout(1)

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
                continue

    print("✅ Proxy shut down cleanly.")

if __name__ == "__main__":
    start_proxy()
