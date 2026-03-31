"""
Internet-based peer discovery via the Obscura47 bootstrap registry.

Nodes call `register_with_registry()` on startup and periodically to heartbeat.
Proxies call `fetch_peers_from_registry()` to get internet-wide peers.

Supports ECDSA challenge-response auth when a node provides its ECC private key.
"""

import json
import time
import threading
import urllib.request
from typing import List, Dict
from src.utils.config import REGISTRY_URL, REGISTRY_HEARTBEAT_INTERVAL, PEER_EXPIRY_SECONDS


def register_with_registry(role: str, port: int, pub: str | None = None,
                           priv_key=None, ws_port: int | None = None):
    """
    Register this node with the bootstrap registry.
    If pub + priv_key are provided, performs ECDSA challenge-response auth.
    """
    body: dict = {"role": role, "port": port}
    if pub:
        body["pub"] = pub
    if ws_port:
        body["ws_port"] = ws_port

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

        if result.get("ok"):
            # Registered (heartbeat or no-auth)
            print(f"[internet] Registered as {role} with registry (your_ip={result.get('your_ip')})")
            return result

        # Challenge-response flow
        challenge = result.get("challenge")
        peer_id = result.get("peer_id")
        if challenge and peer_id and priv_key and pub:
            from src.core.encryptions import ecdsa_sign
            signature = ecdsa_sign(priv_key, challenge.encode())

            verify_body = json.dumps({
                "peer_id": peer_id,
                "signature": signature,
            }).encode()
            verify_req = urllib.request.Request(
                f"{REGISTRY_URL}/register/verify",
                data=verify_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(verify_req, timeout=5) as verify_resp:
                verify_result = json.loads(verify_resp.read())

            if verify_result.get("ok"):
                print(f"[internet] Verified as {role} with registry (your_ip={verify_result.get('your_ip')})")
                return verify_result
            else:
                print(f"[internet] Verification failed: {verify_result}")
                return None
        else:
            print(f"[internet] Challenge received but no private key to sign with")
            return None

    except Exception as e:
        print(f"[internet] Failed to register with registry: {e}")
        return None


def heartbeat_loop(role: str, port: int, pub: str | None = None,
                   priv_key=None, ws_port: int | None = None):
    """Periodically re-register to keep this node alive in the registry."""
    while True:
        register_with_registry(role, port, pub, priv_key=priv_key, ws_port=ws_port)
        time.sleep(REGISTRY_HEARTBEAT_INTERVAL)


def start_heartbeat(role: str, port: int, pub: str | None = None,
                    priv_key=None, ws_port: int | None = None):
    """Start the heartbeat in a background daemon thread."""
    t = threading.Thread(
        target=heartbeat_loop,
        args=(role, port, pub),
        kwargs={"priv_key": priv_key, "ws_port": ws_port},
        daemon=True,
    )
    t.start()
    return t


def fetch_peers_from_registry(role_filter: str | None = None) -> List[Dict]:
    """Fetch the full peer list from the bootstrap registry."""
    url = f"{REGISTRY_URL}/peers"
    if role_filter:
        url += f"?role={role_filter}"
    req = urllib.request.Request(url, method="GET")
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
    Now parses ws_port from registry responses.
    """
    remote = fetch_peers_from_registry(role_filter=role_filter)
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
            if p.get("ws_port"):
                entry["ws_port"] = p["ws_port"]
            target_list.append(entry)
            print(f"[internet] Discovered {p.get('role', '?')} at {p['host']}:{p['port']}"
                  + (f" (ws:{p['ws_port']})" if p.get('ws_port') else ""))
        else:
            # Update ws_port on existing entries if newly available
            for ep in target_list:
                if ep["host"] == p["host"] and ep["port"] == p["port"]:
                    if p.get("ws_port") and not ep.get("ws_port"):
                        ep["ws_port"] = p["ws_port"]
                    ep["ts"] = now
                    break

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
