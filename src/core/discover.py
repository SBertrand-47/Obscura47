import socket
import json
import struct
import time

MULTICAST_GROUP = "239.255.255.250"  # Multicast address for LAN
DEFAULT_MULTICAST_PORT = 50000  # Default discovery port for clients
NODE_MULTICAST_PORT = 50001  # Separate discovery port for nodes

def broadcast_discovery(multicast_port=DEFAULT_MULTICAST_PORT):
    """Sends a multicast message to discover other nodes."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        message = json.dumps({"type": "discovery_request"}).encode()
        sock.sendto(message, (MULTICAST_GROUP, multicast_port))
        print(f"🔍 Sent multicast discovery request on port {multicast_port}...")

def listen_for_discovery(peers, multicast_port=DEFAULT_MULTICAST_PORT):
    """Listens for multicast discovery requests and responds with node info."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", multicast_port))

        mreq = struct.pack("=4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print(f"👂 Listening for discovery requests on multicast {MULTICAST_GROUP}:{multicast_port}...")

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode())

                if message.get("type") == "discovery_request":
                    response = json.dumps({"type": "discovery_response", "host": addr[0], "port": 5001}).encode()
                    sock.sendto(response, addr)
                    print(f"✅ Responded to discovery request from {addr[0]}")

                elif message.get("type") == "discovery_response":
                    new_peer = {"host": message["host"], "port": message["port"]}
                    if new_peer not in peers:
                        peers.append(new_peer)
                        print(f"🔗 Discovered new peer: {new_peer}")

            except Exception as e:
                print(f"⚠️ Error in discovery listener: {e}")
                time.sleep(1)  # Prevents infinite error loops
