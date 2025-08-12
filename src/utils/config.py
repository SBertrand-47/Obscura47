import os


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

# Onion/observability
ONION_ONLY = getenv_str("OBSCURA_ONION_ONLY", "false").lower() in ("1", "true", "yes")
JSON_LOGS = getenv_str("OBSCURA_JSON_LOGS", "false").lower() in ("1", "true", "yes")


# Persistent key paths (role-specific)
NODE_KEY_PATH = getenv_str("OBSCURA_NODE_KEY_PATH", os.path.join(os.path.expanduser("~"), ".obscura47", "node_key.pem"))
EXIT_KEY_PATH = getenv_str("OBSCURA_EXIT_KEY_PATH", os.path.join(os.path.expanduser("~"), ".obscura47", "exit_key.pem"))


# Back-compat aliases used by some modules
NODE_MULTICAST_PORT = NODE_DISCOVERY_PORT
EXIT_NODE_MULTICAST_PORT = EXIT_DISCOVERY_PORT


