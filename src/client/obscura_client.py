import threading
import time
from src.core.discover import broadcast_discovery, listen_for_discovery

class ObscuraClient:
    def __init__(self):
        self.peers = []  # Stores discovered nodes
        self.running = True

        # Start peer discovery listeners (Make sure they use the right ports!)
        threading.Thread(target=self.listen_for_proxies, daemon=True).start()
        threading.Thread(target=self.listen_for_nodes, daemon=True).start()
        
        # Start continuous discovery requests
        threading.Thread(target=self.continuous_discovery, daemon=True).start()

    def listen_for_proxies(self):
        """Listen for proxy discovery responses (port 50000)."""
        print("👂 Listening for proxies on port 50000...")
        listen_for_discovery(self.peers, multicast_port=50000)

    def listen_for_nodes(self):
        """Listen for node discovery responses (port 50002)."""
        print("👂 Listening for relay nodes on port 50002...")
        listen_for_discovery(self.peers, multicast_port=50002)

    def continuous_discovery(self):
        """Continuously sends discovery requests for nodes & proxies every 5s."""
        while self.running:
            print("🔍 Broadcasting discovery requests...")
            broadcast_discovery(50000)  # Discover proxies
            broadcast_discovery(50002)  # Discover relay nodes
            time.sleep(5)  # Broadcast every 5 seconds

    def start(self):
        """Starts discovery process."""
        print("🚀 Obscura47 Client Discovery Started")

if __name__ == "__main__":
    client = ObscuraClient()
    client.start()
    
    # Keep script running
    while True:
        time.sleep(1)
