import threading
import time
from src.core.discover import broadcast_discovery, listen_for_discovery

CLIENT_DISCOVERY_PORT = 50000  # Separate discovery port for clients

class ObscuraClient:
    def __init__(self):
        self.peers = []  # Stores discovered peers
        self.running = True

        # Start peer discovery listener in a background thread
        threading.Thread(
            target=listen_for_discovery,
            args=(self.peers, CLIENT_DISCOVERY_PORT),  # Use separate client discovery port
            daemon=True
        ).start()

    def discover_peers(self):
        """Continuously broadcasts discovery requests to find new peers."""
        while self.running:
            broadcast_discovery(CLIENT_DISCOVERY_PORT)  # Use separate client discovery port
            time.sleep(5)  # Send a request every 5 seconds

    def start(self):
        """Starts the client discovery broadcasting."""
        print(f"🚀 Obscura47 Client Discovery Started on port {CLIENT_DISCOVERY_PORT}")
        threading.Thread(
            target=self.discover_peers,
            daemon=True
        ).start()

    def stop(self):
        """Stops discovery broadcasting (cleanup)."""
        self.running = False
        print("🛑 Stopping Obscura47 Client Discovery...")

if __name__ == "__main__":
    client = ObscuraClient()
    client.start()

    try:
        while True:
            time.sleep(1)  # Keep running
    except KeyboardInterrupt:
        client.stop()  # Gracefully stop discovery
