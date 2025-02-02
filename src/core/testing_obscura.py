import time
import threading
from core.node import ObscuraNode
from core.exit_node import ExitNode

def start_node(port, peers):
    """Start a node with a given port and peer list."""
    node = ObscuraNode(port=port, peers=peers)
    node.run()

def start_exit_node(port):
    """Start the exit node."""
    exit_node = ExitNode(host="127.0.0.1", port=port)
    exit_node.start_server()

# Setup test environment
if __name__ == "__main__":
    # Define nodes and their connections
    nodes = [
        {"host": "127.0.0.1", "port": 5001, "peers": [{"host": "127.0.0.1", "port": 5002}]},
        {"host": "127.0.0.1", "port": 5002, "peers": [{"host": "127.0.0.1", "port": 5003}]},
        {"host": "127.0.0.1", "port": 5003, "peers": [{"host": "127.0.0.1", "port": 6000}]}  # Last relay -> exit node
    ]
    
    exit_node_port = 6000

    # Start the three relay nodes
    for node_config in nodes:
        threading.Thread(
            target=start_node,
            args=(node_config["port"], node_config["peers"]),
            daemon=True
        ).start()

    # Start the exit node
    threading.Thread(
        target=start_exit_node,
        args=(exit_node_port,),
        daemon=True
    ).start()

    # Give nodes time to start
    time.sleep(3)

    # Send a test request from Node A (first node in chain)
    print("🚀 Sending test request through Obscura47 network...")
    client_node = ObscuraNode(port=5001, peers=[{"host": "127.0.0.1", "port": 5002}])
    client_node.router.relay_message(
        "https://www.google.com",
        {"host": "127.0.0.1", "port": 6000}  # The exit node
    )

    # Keep script running to observe logs
    input("Press Enter to stop test...\n")
