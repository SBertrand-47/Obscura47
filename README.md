# Obscura47

Obscura47 is a Python-based anonymous overlay network that routes TCP traffic through 4 to 7 encrypted hops using onion layering. It includes dual transport support through WebSocket and TCP, a FastAPI registry for peer discovery, ECDSA challenge-response authentication, guard-node pinning, and bidirectional reverse channels for NAT traversal.

**Want to help the network grow?** Clone the repo, run one command, and contribute bandwidth as a relay node. No extra configuration required.

## Quick Join

```bash
git clone https://github.com/your-repo/Obscura47.git
cd Obscura47
pip install -r requirement.txt
python join_network.py
