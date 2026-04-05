# Obscura47

Obscura47 is a small Tor-style overlay network written in Python. It routes
TCP traffic through 4–7 encrypted hops using onion layering, with a pluggable
transport (WebSocket or legacy TCP), a FastAPI registry for internet-wide peer
discovery, ECDSA challenge-response auth, and Tor-style guard-node pinning.

It is a research / learning project, not a drop-in Tor replacement. See
[Security & threat model](#security--threat-model) below before running it on
anything you care about.

## Architecture

```
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
                                  │                                                 │
                                  └─────────────── return path (ws or tcp) ─────────┘
```

**Roles:**

- **Proxy** — runs on the client machine, terminates HTTP/HTTPS CONNECT, builds
  circuits, pins guards, enforces per-client policy.
- **Node (relay)** — middle hop. Decrypts one onion layer, forwards to the next.
- **Exit node** — egress hop. Opens the TCP connection to the origin, streams
  bytes back along the return path. Enforces DoH + private-IP/domain policy.
- **Registry** — FastAPI + SQLite (WAL). Nodes register via ECDSA
  challenge-response; clients fetch live peer lists. Optional TLS.

**Discovery** works via both LAN multicast (zero-config on a single network)
and the internet registry.

## Features

- **Onion routing**, 4–7 hops, ECDH P-256 + AES-GCM per layer
- **Guard-node pinning** — persistent first-hop commitment (Tor-style),
  mitigates the "eventually you pick a malicious guard" exposure
- **Dual transport** — WebSocket (ws:// or wss://) with fallback to raw TCP,
  persistent connection pools, backpressure queues, idle sweepers
- **ECDSA challenge-response auth** between nodes and registry (uses the
  existing P-256 keypairs — no separate JWT/API-key)
- **TLS rollout** — per-peer `ws_tls` flag so plaintext and wss:// peers can
  coexist during migration
- **Exit policy** — DoH (A/AAAA), private-IP block list, domain allow/deny
- **Tunnel controls** — per-circuit byte and time caps, per-IP tunnel limits,
  concise + JSON log modes, periodic metrics
- **Persistence** — registry SQLite, guard set JSON, exit health file,
  long-lived ECC keys on disk

## Quick start

Python 3.12+.

```bash
pip install -r requirement.txt
cp .env.example .env       # optional — all vars have defaults
```

In four terminals, run:

```bash
python -m src.main registry                 # FastAPI on :8470
python -m src.main exit     --port 6000     # exit node + ws on :6001
python -m src.main node     --port 5001     # relay + ws on :5002
python -m src.main proxy                    # local HTTP proxy on :9047
```

Then point a client at the proxy:

```bash
curl -x 127.0.0.1:9047 https://example.com
```

For a single-machine smoke test that spins up echo + relay + exit + proxy
with injected peers (no registry, no multicast), see
[`tests/test_guards.py`](tests/test_guards.py) and the router unit tests.

## Configuration

All settings are environment variables — see [`.env.example`](.env.example) for
the full annotated list. The most commonly tweaked:

| Variable | Default | Purpose |
|---|---|---|
| `OBSCURA_PROXY_PORT` | `9047` | Local HTTP/CONNECT listener |
| `OBSCURA_REGISTRY_URL` | `http://localhost:8470` | Registry endpoint for internet discovery |
| `OBSCURA_PREFER_WEBSOCKET` | `true` | Prefer ws/wss over raw TCP when peer advertises a ws_port |
| `OBSCURA_ONION_ONLY` | `false` | Reject legacy non-onion frames |
| `OBSCURA_GUARD_ENABLED` | `true` | Pin first-hop to a persistent guard set |
| `OBSCURA_GUARD_COUNT` | `3` | Size of the guard set |
| `OBSCURA_WS_TLS_CERT` / `_KEY` | unset | Enable `wss://` on node/exit ports |
| `OBSCURA_REGISTRY_TLS_CERT` / `_KEY` | unset | Enable `https://` on registry |
| `OBSCURA_TLS_VERIFY` | `true` | Verify cert chain client-side (disable only for self-signed dev) |
| `OBSCURA_EXIT_DENY_PRIVATE_IPS` | `true` | Block exits to RFC1918 + loopback |
| `OBSCURA_PROXY_TOKEN` | unset | Require `Proxy-Token` header on local proxy |

Persistent state lives under `~/.obscura47/`:

- `node_key.pem`, `exit_key.pem` — long-lived ECC keypairs
- `guards.json` — proxy's pinned guard set

## Running the tests

```bash
python -m pytest tests/ -q --ignore=tests/test_e2e_tunnel.py
```

The full unit suite covers encryption primitives, the registry API,
WebSocket transport, router behavior, guard-set logic, and TLS handshakes
(66 tests, all green). `test_e2e_tunnel.py` is skipped by default — it
spawns real node/exit/proxy processes and is slow.

## Security & threat model

**What Obscura47 aims to defend against:**

- A passive network observer between two consecutive hops (they see only
  encrypted frames and the next-hop address).
- A compromised middle relay (it sees only its predecessor and successor,
  never the client, the destination, or the payload).
- Statistical guard-discovery attacks — pinning caps per-client exposure.

**What it does not defend against:**

- An adversary that observes *both* the client's local network and the
  exit's network simultaneously. End-to-end traffic correlation is out of
  scope (same as Tor, without any extra padding/timing mitigations).
- A malicious exit seeing unencrypted application-layer traffic. Use
  end-to-end TLS (i.e. `https://`) always.
- A malicious registry serving crafted peer lists. TLS-verify the registry
  (`OBSCURA_REGISTRY_URL=https://…`, `OBSCURA_TLS_VERIFY=true`) and run
  your own.
- Local host compromise, side channels, key exfiltration via disk access.
- Application-layer fingerprinting (browser, TLS ClientHello, etc.).

**Known limitations / things to be aware of:**

- The `ONION_ONLY=false` default still accepts legacy AES-CFB frames for
  backward compatibility. Flip to `true` in production.
- Guard pinning is proxy-local — there is no consensus directory authority.
- The registry is first-come-first-served; there is no operator vetting.
  Anyone can register a node.
- No traffic padding, no circuit rotation policy beyond guards, no defense
  against timing attacks.

## Project layout

```
src/
  main.py              # CLI entry point (proxy | node | exit | registry)
  core/
    proxy.py           # HTTP CONNECT termination + tunnel orchestration
    node.py            # Relay node (dual-protocol TCP + WebSocket)
    exit_node.py       # Exit node (egress, DoH, policy)
    router.py          # Route building, onion layering, frame dispatch
    guards.py          # First-hop guard pinning
    encryptions.py     # ECDH P-256 + AES-GCM + ECDSA primitives
    ws_transport.py    # WebSocket server + client pool (wss-aware)
    registry.py        # Thin wrapper that runs registry_server.py
    internet_discovery.py  # Registry auth + peer fetch loop
    discover.py        # LAN multicast discovery
  utils/
    config.py          # Env var loading (single source of truth)
    logger.py
registry_server.py     # Standalone FastAPI + SQLite registry
tests/                 # pytest suite
.env.example           # Annotated config reference
```

## Contributing

Bug reports and PRs welcome. If your change touches the transport or the
routing path, please add a test in `tests/` and verify the full suite passes
before submitting.
