import socket
import json
import struct
import time

MULTICAST_GROUP = "239.255.255.250"
DEFAULT_MULTICAST_PORT = 50000  # Default discovery port for clients
NODE_MULTICAST_PORT = 50001     # Default discovery port for nodes

def broadcast_discovery(multicast_port=DEFAULT_MULTICAST_PORT):
    """
    Sends a multicast message to discover other nodes.
    By default, uses DEFAULT_MULTICAST_PORT (50000) for client discovery,
    or can use NODE_MULTICAST_PORT (50001) for node discovery.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        message = json.dumps({"type": "discovery_request"}).encode()
        sock.sendto(message, (MULTICAST_GROUP, multicast_port))
        print(f"🔍 Sent multicast discovery request on port {multicast_port}...")

def listen_for_discovery(peers, local_port=5001, multicast_port=DEFAULT_MULTICAST_PORT):
    """
    Listens for multicast discovery requests and responds with node/client info.
    :param peers: the shared list of discovered peers.
    :param local_port: the TCP port on which *this* process is listening
                       (so we can advertise ourselves correctly).
    :param multicast_port: which multicast port to bind for discovery listening.
    """
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

                # Our local IP: the IP *this* socket is bound to
                local_ip = sock.getsockname()[0]

                if message.get("type") == "discovery_request":
                    # Respond with THIS machine's IP and port
                    response = json.dumps({
                        "type": "discovery_response",
                        "host": local_ip,
                        "port": local_port
                    }).encode()
                    sock.sendto(response, addr)
                    print(f"✅ Responded to discovery request from {addr[0]} with host={local_ip}, port={local_port}")

                elif message.get("type") == "discovery_response":
                    # We discovered a new peer
                    new_peer = {"host": message["host"], "port": message["port"]}
                    if new_peer not in peers:
                        peers.append(new_peer)
                        print(f"🔗 Discovered new peer: {new_peer}")

            except Exception as e:
                print(f"⚠️ Error in discovery listener: {e}")
                time.sleep(1)
