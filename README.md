# Obscura47

Obscura47 is a Tor-style anonymous overlay network written in Python. It routes
TCP traffic through 4–7 encrypted hops using onion layering, with dual transport
(WebSocket + TCP), a FastAPI registry for internet-wide peer discovery, ECDSA
challenge-response auth, guard-node pinning, and bidirectional reverse channels
for NAT traversal.

**Want to help the network grow?** Clone, run one command, and you're
contributing bandwidth as a relay node. No configuration needed.

## Quick Join (for contributors)

```bash
git clone https://github.com/your-repo/Obscura47.git
cd Obscura47
pip install -r requirements.txt
python join_network.py
```

That's it. The interactive menu lets you pick your role. Or go headless:

```bash
python join_network.py node          # Relay node (recommended)
python join_network.py node+exit     # Both relay and exit
```

For the shared public network, contributors should point `OBSCURA_REGISTRY_URL`
at `https://db.monmedjs.com`.

On Windows, double-click `Obscura47.exe` if you have the pre-built binary,
or run the tray app to keep it in the background:

```bash
python tray_app.py                   # Sits in system tray, runs as relay
python tray_app.py node+exit         # Tray mode, relay + exit
```

## Architecture

```text
             ┌──────────────┐   ECDSA auth + heartbeat    ┌──────────────┐
             │   Registry   │ ◄──────────────────────────►│    Nodes     │
             │  (FastAPI +  │                             │ (relay/exit) │
             │   SQLite)    │                             └──────────────┘
             └──────────────┘                                    ▲
                                                                 │ WS / wss / TCP
                                                                 ▼
┌────────┐   HTTP CONNECT   ┌────────┐  onion frame  ┌────────┐  onion frame  ┌────────┐   plain    ┌────────┐
│ client │ ───────────────► │ proxy  │ ────────────► │ relay  │ ────────────► │  exit  │ ────────► │ origin │
└────────┘                  └────────┘               │ (guard)│  … 3–6 hops … └────────┘           └────────┘
                                 ▲                    └────────┘                   │
                                 │         reverse channel (same connections)      │
                                 └─────────────────────────────────────────────────┘
```

**Roles:**

- **Proxy**: runs on the client machine. Terminates HTTP CONNECT, builds
  onion circuits, pins guards, enforces per-client policy. Responses flow
  back through reverse channels on the same connections (NAT-friendly).
- **Node (relay)**: middle hop. Peels one onion layer, forwards to the next.
  Stores reverse channel so responses can flow back.
- **Exit node**: egress hop. Opens the TCP connection to the origin, streams
  bytes back through the reverse channel. Requires admin approval to prevent
  abuse.
- **Registry**: FastAPI + SQLite. Nodes register via ECDSA challenge-response;
  clients fetch live peer lists. Includes admin controls, kill switch, and
  exit node approval workflow.

## Features

- **Onion routing**: 4–7 hops, ECDH P-256 + AES-GCM per layer, onion-only
- **Bidirectional reverse channels**: responses flow back on the same connections
  that carried requests, solving NAT traversal without requiring inbound ports
- **Guard-node pinning**: persistent first-hop commitment (Tor-style)
- **Dual transport**: WebSocket (ws/wss) preferred, TCP fallback, persistent
  connection pools with backpressure
- **ECDSA challenge-response auth**: nodes prove identity to the registry using
  their existing P-256 keypairs
- **Exit node approval**: new exits require admin approval before receiving
  traffic, preventing unauthorized egress nodes
- **Admin kill switch**: dual-layer (registry broadcast + ECDSA-signed token)
  allows the network operator to shut down all nodes remotely
- **System tray mode**: runs in the background on Windows/macOS/Linux with a
  tray icon showing status
- **Health monitoring**: configurable node health checks, exit scoring with
  RTT-based selection and exponential backoff
- **Tunnel controls**: per-circuit byte/time caps, per-IP limits, idle sweepers

## Installation

Python 3.10+.

```bash
pip install -r requirements.txt
cp .env.example .env       # optional, all vars have defaults
```

## Ways to Run

### 1. Quick Join (easiest)
```bash
python join_network.py              # Interactive menu
python join_network.py node         # Relay node
python join_network.py exit         # Exit node
python join_network.py node+exit    # Both
```

### 2. System Tray (background)
```bash
python tray_app.py                  # Tray icon, relay node
python tray_app.py node+exit        # Tray icon, relay + exit
```

### 3. Desktop GUI
```bash
python app.py                       # Full Tkinter dashboard
```

### 4. CLI (individual components)
```bash
python -m src.main registry         # Bootstrap registry on :8470
python -m src.main exit --port 6000 # Exit node + ws on :6001
python -m src.main node --port 5001 # Relay + ws on :5002
python -m src.main proxy            # Local proxy on :9047
```

### 5. Pre-built Binaries
```bash
# Build (requires pyinstaller)
./build_mac.sh                      # macOS
./build_linux.sh                    # Linux
build_windows.bat                   # Windows

# Run
./dist/Obscura47-CLI node           # CLI binary
open dist/Obscura47.app             # macOS GUI
dist\Obscura47.exe                  # Windows GUI
```

Then point a client at the proxy:

```bash
curl -x 127.0.0.1:9047 https://example.com
```

## Operator Tools

Most users and contributors do not need any admin tooling. The standard
contributor path is `join_network.py`, the tray app, or the main runtime roles
under `src.main`.

`admin_cli.py` is for the network operator only. It manages exit approval,
peer removal, and the signed kill-switch workflow against a registry you
control.

Important safety rules:

- Never commit `.env`, admin tokens, or generated admin keys.
- `admin_cli.py keygen` writes operator keys to `~/.obscura47/`, not the repo.
- Leave `OBSCURA_REGISTRY_ADMIN_KEY` empty in sample configs and only set it in
  your private deployment environment.
- If you are just contributing bandwidth as a relay or exit, you can ignore
  `admin_cli.py` entirely.

## Configuration

All settings are environment variables. See [`.env.example`](.env.example) for
the full annotated list. The most commonly tweaked:

| Variable | Default | Purpose |
|---|---|---|
| `OBSCURA_PROXY_PORT` | `9047` | Local HTTP CONNECT listener |
| `OBSCURA_REGISTRY_URL` | `https://db.monmedjs.com` | Registry endpoint for discovery on the shared public network |
| `OBSCURA_PREFER_WEBSOCKET` | `true` | Prefer ws/wss over raw TCP |
| `OBSCURA_GUARD_ENABLED` | `true` | Pin first-hop to a persistent guard set |
| `OBSCURA_GUARD_COUNT` | `3` | Size of the guard set |
| `OBSCURA_WS_TLS_CERT` / `_KEY` | unset | Enable `wss://` on node/exit ports |
| `OBSCURA_REGISTRY_TLS_CERT` / `_KEY` | unset | Enable `https://` on registry |
| `OBSCURA_EXIT_DENY_PRIVATE_IPS` | `true` | Block exits to RFC1918 + loopback |
| `OBSCURA_PROXY_TOKEN` | unset | Require `Proxy-Token` header on local proxy |

Persistent state lives under `~/.obscura47/`:

- `node_key.pem`, `exit_key.pem`, `proxy_key.pem`: long-lived ECC keypairs
- `guards.json`: proxy's pinned guard set

## Network Roles Explained

**As a relay node**, your machine forwards encrypted blobs between other nodes.
You can't see the content, the source, or the destination, just opaque
encrypted packets. This is the safest and easiest way to contribute.

**As an exit node**, your machine makes the actual connection to the destination
website. Your IP is what the website sees. Exit nodes require admin approval
before they receive traffic. Only run an exit if you understand the implications.

**As a proxy user**, you browse the internet through the Obscura network. Your
traffic is encrypted through 4–7 hops before reaching the exit. Configure your
browser to use `127.0.0.1:9047` as an HTTP proxy.

## Running the Tests

```bash
python -m pytest tests/ -q --ignore=tests/test_e2e_tunnel.py
```

## Security & Threat Model

**What Obscura47 defends against:**

- A passive network observer between two consecutive hops (they see only
  encrypted frames and the next-hop address).
- A compromised middle relay (it sees only its predecessor and successor,
  never the client, the destination, or the payload).
- Statistical guard-discovery attacks, pinning caps per-client exposure.
- NAT traversal, reverse channels mean neither proxy nor relay need
  inbound ports reachable from the internet.

**What it does not defend against:**

- An adversary observing both the client's network and the exit's network
  simultaneously (end-to-end traffic correlation).
- A malicious exit seeing unencrypted application-layer traffic, always use
  HTTPS.
- Application-layer fingerprinting (browser, TLS ClientHello, etc.).
- No traffic padding, no circuit rotation policy beyond guards.

## Project Layout

```text
src/
  main.py               # CLI entry point (proxy | node | exit | registry)
  core/
    proxy.py            # HTTP CONNECT termination + tunnel orchestration
    node.py             # Relay node (dual-protocol TCP + WebSocket)
    exit_node.py        # Exit node (egress, reverse channel responses)
    router.py           # Route building, onion layering, frame dispatch
    guards.py           # First-hop guard pinning
    encryptions.py      # ECDH P-256 + AES-GCM + ECDSA primitives
    ws_transport.py     # WebSocket server + client pool (wss-aware)
    registry.py         # Thin wrapper that runs registry_server.py
    internet_discovery.py  # Registry auth + peer fetch + kill switch monitor
    discover.py         # LAN multicast discovery
  utils/
    config.py           # Env var loading (single source of truth)
    logger.py
registry_server.py      # Standalone FastAPI + SQLite registry
app.py                  # Desktop GUI (Tkinter)
tray_app.py             # System tray background mode
join_network.py         # Quick-join script
build_windows.bat       # Windows build script
build_mac.sh            # macOS build script
build_linux.sh          # Linux build script
.env.example            # Annotated config reference
tests/                  # pytest suite
```

## Contributing

Bug reports and PRs welcome. The more relay nodes on the network, the better
the anonymity for everyone. If your change touches the transport or the routing
path, please add a test and verify the suite passes before submitting.
