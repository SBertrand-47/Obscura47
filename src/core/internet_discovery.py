"""
Internet-based peer discovery via the Obscura47 bootstrap registry.

Nodes call `register_with_registry()` on startup and periodically to heartbeat.
Proxies call `fetch_peers_from_registry()` to get internet-wide peers.
"""

import json
import time
import threading
import urllib.request
from typing import List, Dict
from src.utils.config import REGISTRY_URL, REGISTRY_HEARTBEAT_INTERVAL, PEER_EXPIRY_SECONDS


def register_with_registry(role: str, port: int, pub: str | None = None):
    """Register this node with the bootstrap registry (one-shot)."""
    body: dict = {"role": role, "port": port}
    if pub:
        body["pub"] = pub
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/register",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            print(f"[internet] Registered as {role} with registry (your_ip={result.get('your_ip')})")
            return result
    except Exception as e:
        print(f"[internet] Failed to register with registry: {e}")
        return None


def heartbeat_loop(role: str, port: int, pub: str | None = None):
    """Periodically re-register to keep this node alive in the registry."""
    while True:
        register_with_registry(role, port, pub)
        time.sleep(REGISTRY_HEARTBEAT_INTERVAL)


def start_heartbeat(role: str, port: int, pub: str | None = None):
    """Start the heartbeat in a background daemon thread."""
    t = threading.Thread(target=heartbeat_loop, args=(role, port, pub), daemon=True)
    t.start()
    return t


def fetch_peers_from_registry() -> List[Dict]:
    """Fetch the full peer list from the bootstrap registry."""
    req = urllib.request.Request(f"{REGISTRY_URL}/peers", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            peers = json.loads(resp.read())
            return peers if isinstance(peers, list) else []
    except Exception as e:
        print(f"[internet] Failed to fetch peers from registry: {e}")
        return []


def merge_internet_peers(target_list: List[Dict], role_filter: str | None = None):
    """
    Fetch peers from the registry and merge them into a local peer list.
    `role_filter` can be "node", "exit", or None for all.
    """
    remote = fetch_peers_from_registry()
    now = time.time()
    for p in remote:
        if role_filter and p.get("role") != role_filter:
            continue
        # Don't duplicate
        exists = any(
            ep["host"] == p["host"] and ep["port"] == p["port"]
            for ep in target_list
        )
        if not exists:
            entry = {"host": p["host"], "port": p["port"], "ts": now}
            if p.get("pub"):
                entry["pub"] = p["pub"]
            target_list.append(entry)
            print(f"[internet] Discovered {p.get('role', '?')} at {p['host']}:{p['port']}")

    # Expire old peers
    cutoff = now - PEER_EXPIRY_SECONDS
    target_list[:] = [p for p in target_list if p.get("ts", 0) >= cutoff]


def internet_discovery_loop(relay_peers: List[Dict], exit_peers: List[Dict], interval: int = 15):
    """Periodically fetch peers from the registry and merge into local lists."""
    while True:
        merge_internet_peers(relay_peers, role_filter="node")
        merge_internet_peers(exit_peers, role_filter="exit")
        time.sleep(interval)


def start_internet_discovery(relay_peers: List[Dict], exit_peers: List[Dict], interval: int = 15):
    """Start internet discovery in a background daemon thread."""
    t = threading.Thread(
        target=internet_discovery_loop,
        args=(relay_peers, exit_peers, interval),
        daemon=True,
    )
    t.start()
    return t
