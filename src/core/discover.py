import socket
import json
import struct
import time

MULTICAST_GROUP = "239.255.255.250"
DISCOVERY_PORT = 50000  # Clients/Proxy discovery
NODE_MULTICAST_PORT = 50002  # Nodes should be using this!
EXIT_NODE_MULTICAST_PORT = 50003  # Exit node discovery

def get_local_ip():
    """Returns the machine's LAN IP (avoids 127.0.0.1)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"

def broadcast_discovery(multicast_port=DISCOVERY_PORT):
    """Broadcasts a discovery request to find other nodes or clients."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            message = json.dumps({"type": "discovery_request"}).encode()
            sock.sendto(message, (MULTICAST_GROUP, multicast_port))
            print(f"🔍 Sent multicast discovery request on port {multicast_port}...")
    except Exception as e:
        print(f"❌ Error broadcasting discovery request: {e}")

def listen_for_discovery(peers, local_port=5001, multicast_port=DISCOVERY_PORT):
    """Listens for discovery requests and responds with node info."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", multicast_port))

            mreq = struct.pack("=4sl", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            print(f"👂 Listening for discovery on {MULTICAST_GROUP}:{multicast_port}...")

            advertised_ip = get_local_ip()

            while True:
                try:
                    data, addr = sock.recvfrom(1024)
                    message = json.loads(data.decode())

                    print(f"📩 Received discovery message from {addr}: {message}")

                    if message.get("type") == "discovery_request":
                        response = json.dumps({
                            "type": "discovery_response",
                            "host": advertised_ip,  
                            "port": local_port      
                        }).encode()
                        sock.sendto(response, addr)
                        print(f"✅ Responded to discovery from {addr[0]} with {advertised_ip}:{local_port}")

                    elif message.get("type") == "discovery_response":
                        new_peer = {"host": message["host"], "port": message["port"]}
                        if new_peer not in peers and new_peer["host"] != advertised_ip:
                            peers.append(new_peer)
                            print(f"🔗 Discovered new peer: {new_peer}")

                except json.JSONDecodeError:
                    print("⚠️ Received malformed discovery message. Ignoring.")
                except Exception as e:
                    print(f"⚠️ Error in discovery listener: {e}")
                    time.sleep(1)

    except Exception as e:
        print(f"❌ Error setting up discovery listener: {e}")
