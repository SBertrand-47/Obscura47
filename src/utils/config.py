import os


def _load_dotenv():
    """Load .env file from the project root into os.environ (no dependencies)."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Don't overwrite vars already set in the real environment
            if key and key not in os.environ:
                os.environ[key] = value

_load_dotenv()


def getenv_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def getenv_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


# Network defaults (can be overridden by env)
PROXY_HOST = getenv_str("OBSCURA_PROXY_HOST", "127.0.0.1")
PROXY_PORT = getenv_int("OBSCURA_PROXY_PORT", 9047)
PROXY_RESPONSE_PORT = getenv_int("OBSCURA_PROXY_RESP_PORT", 9051)

DISCOVERY_GROUP = getenv_str("OBSCURA_DISCOVERY_GROUP", "239.255.255.250")
DISCOVERY_PORT = getenv_int("OBSCURA_DISCOVERY_PORT", 50000)
NODE_DISCOVERY_PORT = getenv_int("OBSCURA_NODE_DISCOVERY_PORT", 50002)
EXIT_DISCOVERY_PORT = getenv_int("OBSCURA_EXIT_DISCOVERY_PORT", 50003)

NODE_LISTEN_PORT = getenv_int("OBSCURA_NODE_LISTEN_PORT", 5001)
EXIT_LISTEN_PORT = getenv_int("OBSCURA_EXIT_LISTEN_PORT", 6000)

DISCOVERY_INTERVAL = getenv_int("OBSCURA_DISCOVERY_INTERVAL", 10)

# Discovery/peer management
PEER_EXPIRY_SECONDS = getenv_int("OBSCURA_PEER_EXPIRY_SECONDS", 30)

# Exit health monitoring
EXIT_HEALTH_INTERVAL = getenv_int("OBSCURA_EXIT_HEALTH_INTERVAL", 7)
EXIT_CONNECT_TIMEOUT = float(os.getenv("OBSCURA_EXIT_CONNECT_TIMEOUT", "1.5"))
EXIT_HEALTH_PATH = getenv_str("OBSCURA_EXIT_HEALTH_PATH", "exit_health.json")
EXIT_HEALTH_DECAY = float(os.getenv("OBSCURA_EXIT_HEALTH_DECAY", "0.9"))
EXIT_HEALTH_RTT_ALPHA = float(os.getenv("OBSCURA_EXIT_HEALTH_RTT_ALPHA", "0.5"))

# Exit backoff/blacklist tuning
EXIT_BLACKLIST_FAILS = getenv_int("OBSCURA_EXIT_BLACKLIST_FAILS", 3)
EXIT_FAIL_BACKOFF_BASE = float(os.getenv("OBSCURA_EXIT_FAIL_BACKOFF_BASE", "5"))
EXIT_FAIL_BACKOFF_MAX = float(os.getenv("OBSCURA_EXIT_FAIL_BACKOFF_MAX", "60"))

# Frame/tunnel reliability
FRAME_RETRY_ATTEMPTS = getenv_int("OBSCURA_FRAME_RETRY_ATTEMPTS", 3)
FRAME_RETRY_BASE_DELAY_MS = float(os.getenv("OBSCURA_FRAME_RETRY_BASE_DELAY_MS", "50"))
TUNNEL_MAX_SECONDS = float(os.getenv("OBSCURA_TUNNEL_MAX_SECONDS", "120"))
TUNNEL_MAX_BYTES = int(os.getenv("OBSCURA_TUNNEL_MAX_BYTES", "10485760"))  # 10 MiB
TUNNEL_IDLE_SECONDS = float(os.getenv("OBSCURA_TUNNEL_IDLE_SECONDS", "30"))
CLEANUP_INTERVAL_SECONDS = float(os.getenv("OBSCURA_CLEANUP_INTERVAL_SECONDS", "10"))

# Route retries for message mode
MESSAGE_ROUTE_RETRIES = getenv_int("OBSCURA_MESSAGE_ROUTE_RETRIES", 3)

# Exit DNS/privacy policy
EXIT_DOH_ENDPOINT = getenv_str("OBSCURA_EXIT_DOH_ENDPOINT", "https://cloudflare-dns.com/dns-query")
EXIT_DOH_TIMEOUT = float(os.getenv("OBSCURA_EXIT_DOH_TIMEOUT", "2.0"))
EXIT_DENY_PRIVATE_IPS = getenv_str("OBSCURA_EXIT_DENY_PRIVATE_IPS", "true").lower() in ("1", "true", "yes")
EXIT_ALLOW_DOMAINS = [d.strip() for d in os.getenv("OBSCURA_EXIT_ALLOW_DOMAINS", "").split(",") if d.strip()]
EXIT_DENY_DOMAINS = [d.strip() for d in os.getenv("OBSCURA_EXIT_DENY_DOMAINS", "").split(",") if d.strip()]

# Proxy security
PROXY_TOKEN = getenv_str("OBSCURA_PROXY_TOKEN", "")
MAX_CONCURRENT_TUNNELS = getenv_int("OBSCURA_MAX_CONCURRENT_TUNNELS", 50)
MAX_TUNNELS_PER_IP = getenv_int("OBSCURA_MAX_TUNNELS_PER_IP", 10)

# Persistent channel backpressure
CHANNEL_QUEUE_MAX = getenv_int("OBSCURA_CHANNEL_QUEUE_MAX", 100)
CHANNEL_WRITE_TIMEOUT = float(os.getenv("OBSCURA_CHANNEL_WRITE_TIMEOUT", "2.0"))
CHANNEL_IDLE_CLOSE_SECONDS = float(os.getenv("OBSCURA_CHANNEL_IDLE_CLOSE_SECONDS", "60"))

# General socket connect timeout (seconds) for relay/router TCP connections
SOCKET_CONNECT_TIMEOUT = float(os.getenv("OBSCURA_SOCKET_CONNECT_TIMEOUT", "5.0"))

# Onion/observability
ONION_ONLY = getenv_str("OBSCURA_ONION_ONLY", "false").lower() in ("1", "true", "yes")
JSON_LOGS = getenv_str("OBSCURA_JSON_LOGS", "false").lower() in ("1", "true", "yes")


# Persistent key paths (role-specific)
NODE_KEY_PATH = getenv_str("OBSCURA_NODE_KEY_PATH", os.path.join(os.path.expanduser("~"), ".obscura47", "node_key.pem"))
EXIT_KEY_PATH = getenv_str("OBSCURA_EXIT_KEY_PATH", os.path.join(os.path.expanduser("~"), ".obscura47", "exit_key.pem"))


# Bootstrap registry (internet discovery)
REGISTRY_HOST = getenv_str("OBSCURA_REGISTRY_HOST", "0.0.0.0")
REGISTRY_PORT = getenv_int("OBSCURA_REGISTRY_PORT", 8470)
REGISTRY_URL = getenv_str("OBSCURA_REGISTRY_URL", "http://localhost:8470")
REGISTRY_PEER_TTL = getenv_int("OBSCURA_REGISTRY_PEER_TTL", 120)  # seconds before a peer expires
REGISTRY_HEARTBEAT_INTERVAL = getenv_int("OBSCURA_REGISTRY_HEARTBEAT_INTERVAL", 30)

# WebSocket transport (dual-protocol)
NODE_WS_PORT = getenv_int("OBSCURA_NODE_WS_PORT", 5002)
EXIT_WS_PORT = getenv_int("OBSCURA_EXIT_WS_PORT", 6001)
PROXY_WS_RESPONSE_PORT = getenv_int("OBSCURA_PROXY_WS_RESP_PORT", 9052)
PREFER_WEBSOCKET = getenv_str("OBSCURA_PREFER_WEBSOCKET", "true").lower() in ("1", "true", "yes")

# Registry persistence & auth
REGISTRY_DB_PATH = getenv_str("OBSCURA_REGISTRY_DB_PATH", "registry.db")
REGISTRY_ADMIN_KEY = getenv_str("OBSCURA_REGISTRY_ADMIN_KEY", "")
REGISTRY_RATE_LIMIT = getenv_int("OBSCURA_REGISTRY_RATE_LIMIT", 60)

# ── Guard Nodes (client-side first-hop pinning) ─────────────────
GUARD_ENABLED = getenv_str("OBSCURA_GUARD_ENABLED", "true").lower() in ("1", "true", "yes")
GUARD_COUNT = getenv_int("OBSCURA_GUARD_COUNT", 3)
GUARD_PATH = getenv_str("OBSCURA_GUARD_PATH", os.path.join(os.path.expanduser("~"), ".obscura47", "guards.json"))
# Max age of a guard in days before forced rotation (Tor uses 60-90)
GUARD_LIFETIME_DAYS = getenv_int("OBSCURA_GUARD_LIFETIME_DAYS", 30)
# A guard unseen for this long (seconds) is considered unreachable for selection
GUARD_DOWN_SECONDS = getenv_int("OBSCURA_GUARD_DOWN_SECONDS", 600)

# ── TLS ──────────────────────────────────────────────────────────
# Registry server TLS (serves https:// + wss:// for registry endpoint)
REGISTRY_TLS_CERT = getenv_str("OBSCURA_REGISTRY_TLS_CERT", "")
REGISTRY_TLS_KEY = getenv_str("OBSCURA_REGISTRY_TLS_KEY", "")
# WebSocket transport TLS (serves wss:// on node/exit ws ports)
WS_TLS_CERT = getenv_str("OBSCURA_WS_TLS_CERT", "")
WS_TLS_KEY = getenv_str("OBSCURA_WS_TLS_KEY", "")
# Client-side: set to false to skip TLS cert verification (dev / self-signed)
TLS_VERIFY = getenv_str("OBSCURA_TLS_VERIFY", "true").lower() in ("1", "true", "yes")

# Back-compat aliases used by some modules
NODE_MULTICAST_PORT = NODE_DISCOVERY_PORT
EXIT_NODE_MULTICAST_PORT = EXIT_DISCOVERY_PORT


