import socket
import threading
import random
import json
import time
import signal
import sys
from src.core.router import direct_relay_message
from src.core.discover import broadcast_discovery, listen_for_discovery

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9050
running = True

peers = []
threading.Thread(target=listen_for_discovery, args=(peers,), daemon=True).start()

def handle_browser_request(client_socket):
    global running
    try:
        if not running:
            return

        request = client_socket.recv(4096)
        if not request:
            return

        print(f"🌍 Received browser request (first 100 chars): {request[:100]}...")

        if not peers:
            print("⚠️ No discovered peers yet. Cannot route request.")
            client_socket.close()
            return

        next_hop = random.choice(peers)

        direct_relay_message(json.dumps({"data": request.decode()}), next_hop, peers)
        print("⏳ Waiting for response from the exit node...")

    except Exception as e:
        print(f"❌ Error in handle_browser_request: {e}")
    finally:
        client_socket.close()

def start_proxy():
    global running

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(5)

        print(f"🚀 Proxy running on {PROXY_HOST}:{PROXY_PORT}")

        while running:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handle_browser_request, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue

if __name__ == "__main__":
    start_proxy()
