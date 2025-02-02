import threading
import time
from src.core.discover import broadcast_discovery, listen_for_discovery

class ObscuraClient:
    def __init__(self):
        self.peers = []  # Stores discovered peers
        self.running = True

        # Start peer discovery listener in a background thread
        threading.Thread(
            target=listen_for_discovery,
            args=(self.peers,),
            daemon=True
        ).start()

    def discover_peers(self):
        """Continuously broadcasts discovery requests to find new peers."""
        while self.running:
            broadcast_discovery()
            time.sleep(5)  # Send a request every 5 seconds

    def start(self):
        """Starts the client discovery broadcasting."""
        print("🚀 Obscura47 Client Discovery Started")
        threading.Thread(
            target=self.discover_peers,
            daemon=True
        ).start()

if __name__ == "__main__":
    client = ObscuraClient()
    client.start()

    # Keep running
    while True:
        time.sleep(1)
