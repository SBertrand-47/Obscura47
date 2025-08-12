Obscura47 - Lightweight Onion-style Overlay (MVP)

Overview
Obscura47 provides a Tor-like overlay with multicast discovery, multi-hop encrypted relaying, HTTPS CONNECT tunneling, exit health/selection, and DNS-over-HTTPS at the exit. Payload visibility is avoided; only metadata (request_id, hop counts, exit health) is logged.

Key features
- Multicast discovery with active/passive modes (clients, relays, exits)
- 4–7 hop routing (Route47)
- HTTPS tunneling with streaming and tunnel caps/GC
- Onion message mode: per-hop pubkeys, nodes peel one layer per hop
- Exit health probing (RTT EWMA), backoff/blacklist, persistence
- Exit DoH (A/AAAA), private IP blocking, domain allow/deny
- Security controls: local-only proxy, optional Proxy-Token, per-IP tunnel limits
- Observability: concise logs + JSON logs option, periodic metrics

Quick start
1) Install deps (Python 3.12+):
   pip install -r requirement.txt

2) Start components in separate terminals:
   - Exit:  python -m src.main exit --port 6000
   - Nodes: python -m src.main node --port 5001  (run multiple instances)
   - Proxy: python -m src.main proxy

3) Test HTTP/HTTPS via proxy:
   - curl -x 127.0.0.1:9047 http://example.com
   - curl -x 127.0.0.1:9047 https://example.com

Environment variables (selected)
- OBSCURA_PROXY_PORT (default 9047)
- OBSCURA_DISCOVERY_PORT, OBSCURA_NODE_DISCOVERY_PORT, OBSCURA_EXIT_DISCOVERY_PORT
- OBSCURA_EXIT_HEALTH_INTERVAL, OBSCURA_EXIT_CONNECT_TIMEOUT, OBSCURA_EXIT_HEALTH_PATH
- OBSCURA_EXIT_DOH_ENDPOINT, OBSCURA_EXIT_DENY_PRIVATE_IPS, OBSCURA_EXIT_ALLOW_DOMAINS, OBSCURA_EXIT_DENY_DOMAINS
- OBSCURA_ONION_ONLY (true/false)
- OBSCURA_JSON_LOGS (true/false)
- OBSCURA_MAX_CONCURRENT_TUNNELS, OBSCURA_MAX_TUNNELS_PER_IP
- OBSCURA_CHANNEL_QUEUE_MAX, OBSCURA_CHANNEL_WRITE_TIMEOUT, OBSCURA_CHANNEL_IDLE_CLOSE_SECONDS

Security notes
- Onion mode hides full routes from intermediate nodes when all hops publish pubkeys. Enable ONION_ONLY once validated. For demo compatibility, legacy AES-CFB fallback remains but can be disabled.
- The proxy binds to localhost; enable Proxy-Token to restrict local use further.

Role kits
- Proxy: localhost-only, optional Proxy-Token and tunnel limits. Run: `python -m src.main proxy`.
- Relay Node: middle hop with onion forwarding; persistent key at `~/.obscura47/node_key.pem`. Run: `python -m src.main node --port 5001`.
- Exit Node: egress with DoH and domain/IP policy; persistent key at `~/.obscura47/exit_key.pem`. Run: `python -m src.main exit --port 6000`.

Environment templates (create a file and export before running):
- .env.proxy
  OBSCURA_PROXY_PORT=9047
  OBSCURA_PROXY_RESP_PORT=9051
  OBSCURA_PROXY_TOKEN=changeme

- .env.node
  OBSCURA_NODE_LISTEN_PORT=5001
  OBSCURA_NODE_KEY_PATH=~/.obscura47/node_key.pem

- .env.exit
  OBSCURA_EXIT_LISTEN_PORT=6000
  OBSCURA_EXIT_KEY_PATH=~/.obscura47/exit_key.pem
  OBSCURA_EXIT_DOH_ENDPOINT=https://cloudflare-dns.com/dns-query
  OBSCURA_EXIT_DENY_PRIVATE_IPS=true

Roadmap
- Persistent channels: implemented per-hop with backpressure; optional persistent downstream can be added later.
- Move fully away from AES-CFB once ONION_ONLY is verified.
- Add integration tests (see tests/).


