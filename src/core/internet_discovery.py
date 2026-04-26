"""
Internet-based peer discovery via the Obscura47 bootstrap registry.

Nodes call `register_with_registry()` on startup and periodically to heartbeat.
Proxies call `fetch_peers_from_registry()` to get internet-wide peers.

Supports ECDSA challenge-response auth when a node provides its ECC private key.
"""

import json
import ssl
import time
import threading
import urllib.request
from typing import List, Dict, Callable
from src.utils.config import REGISTRY_URL, REGISTRY_HEARTBEAT_INTERVAL, PEER_EXPIRY_SECONDS, TLS_VERIFY, ADMIN_PUB_PEM, KILL_SWITCH_CHECK_INTERVAL
from src.utils.logger import get_logger

log = get_logger(__name__)

# Public IP as seen by the registry — set on first successful registration.
# Used to filter self out of the peer lists returned by the registry.
_my_public_ip: str | None = None

# Cloudflare (and some WAFs) return 403 for urllib's default User-Agent (Python-urllib/x.x).
_REGISTRY_UA = "Obscura47/1.0 (registry-client)"


def _registry_headers(extra: dict | None = None) -> dict:
    h = {
        "User-Agent": _REGISTRY_UA,
        "Accept": "application/json",
    }
    if extra:
        h.update(extra)
    return h


def _ssl_ctx():
    """Return an SSL context honoring OBSCURA_TLS_VERIFY (None for http:// URLs)."""
    if not REGISTRY_URL.startswith("https://"):
        return None
    if TLS_VERIFY:
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def register_with_registry(role: str, port: int, pub: str | None = None,
                           priv_key=None, ws_port: int | None = None,
                           ws_tls: bool | None = None):
    """
    Register this node with the bootstrap registry.
    If pub + priv_key are provided, performs ECDSA challenge-response auth.
    """
    global _my_public_ip
    body: dict = {"role": role, "port": port}
    if pub:
        body["pub"] = pub
    if ws_port:
        body["ws_port"] = ws_port
    if ws_tls is not None:
        body["ws_tls"] = ws_tls

    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{REGISTRY_URL}/register",
        data=data,
        headers=_registry_headers({"Content-Type": "application/json"}),
        method="POST",
    )
    ctx = _ssl_ctx()
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read())

        if result.get("ok"):
            # Registered (heartbeat or no-auth)
            _my_public_ip = result.get("your_ip") or _my_public_ip
            log.info(f"Registered as {role} with registry (your_ip={_my_public_ip})")
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
                headers=_registry_headers({"Content-Type": "application/json"}),
                method="POST",
            )
            with urllib.request.urlopen(verify_req, timeout=5, context=ctx) as verify_resp:
                verify_result = json.loads(verify_resp.read())

            if verify_result.get("ok"):
                _my_public_ip = verify_result.get("your_ip") or _my_public_ip
                log.info(f"Verified as {role} with registry (your_ip={_my_public_ip})")
                return verify_result
            else:
                log.error(f"Verification failed: {verify_result}")
                return None
        else:
            log.warning(f"Challenge received but no private key to sign with")
            return None

    except Exception as e:
        log.error(f"Failed to register with registry: {e}")
        return None


def heartbeat_loop(role: str, port: int, pub: str | None = None,
                   priv_key=None, ws_port: int | None = None,
                   ws_tls: bool | None = None):
    """Periodically re-register to keep this node alive in the registry."""
    while True:
        register_with_registry(role, port, pub, priv_key=priv_key,
                               ws_port=ws_port, ws_tls=ws_tls)
        time.sleep(REGISTRY_HEARTBEAT_INTERVAL)


def start_heartbeat(role: str, port: int, pub: str | None = None,
                    priv_key=None, ws_port: int | None = None,
                    ws_tls: bool | None = None):
    """Start the heartbeat in a background daemon thread."""
    t = threading.Thread(
        target=heartbeat_loop,
        args=(role, port, pub),
        kwargs={"priv_key": priv_key, "ws_port": ws_port, "ws_tls": ws_tls},
        daemon=True,
    )
    t.start()
    return t


def fetch_peers_from_registry(role_filter: str | None = None) -> List[Dict]:
    """Fetch the full peer list from the bootstrap registry."""
    url = f"{REGISTRY_URL}/peers"
    if role_filter:
        url += f"?role={role_filter}"
    req = urllib.request.Request(url, headers=_registry_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5, context=_ssl_ctx()) as resp:
            peers = json.loads(resp.read())
            return peers if isinstance(peers, list) else []
    except Exception as e:
        log.error(f"Failed to fetch peers from registry: {e}")
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
        # Keep same-IP peers: a local proxy may legitimately need to discover
        # a co-hosted relay or exit that shares its public IP.
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
            if p.get("ws_tls"):
                entry["ws_tls"] = True
            target_list.append(entry)
            log.info(f"Discovered {p.get('role', '?')} at {p['host']}:{p['port']}"
                     + (f" (ws:{p['ws_port']})" if p.get('ws_port') else ""))
        else:
            # Update ws_port on existing entries if newly available
            for ep in target_list:
                if ep["host"] == p["host"] and ep["port"] == p["port"]:
                    if p.get("pub") and not ep.get("pub"):
                        ep["pub"] = p["pub"]
                    if p.get("ws_port") and not ep.get("ws_port"):
                        ep["ws_port"] = p["ws_port"]
                    if p.get("ws_tls") and not ep.get("ws_tls"):
                        ep["ws_tls"] = True
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


def _ecdsa_verify_signature(pub_pem: str, message_bytes: bytes, signature_b64: str) -> bool:
    """
    Verify an ECDSA signature on a message using a public key in PEM format.
    Returns True if signature is valid, False otherwise.
    """
    try:
        from Crypto.PublicKey import ECC
        from Crypto.Signature import DSS
        from Crypto.Hash import SHA256
        import base64

        # Import the public key
        pub_key = ECC.import_key(pub_pem)

        # Decode the signature from base64
        signature_bytes = base64.b64decode(signature_b64)

        # Verify the signature
        verifier = DSS.new(pub_key, mode='fips-186-3', encoding='binary')
        hash_obj = SHA256.new(message_bytes)
        verifier.verify(hash_obj, signature_bytes)
        return True
    except Exception as e:
        log.debug(f"Signature verification failed: {e}")
        return False


def check_network_status() -> dict:
    """
    Check the registry for network status including kill switch state.
    Returns a dict with at least 'kill_active' key.
    On any error, returns {"kill_active": False} (fail-open).
    """
    try:
        req = urllib.request.Request(
            f"{REGISTRY_URL}/network/status",
            headers=_registry_headers(),
            method="GET"
        )
        ctx = _ssl_ctx()
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            result = json.loads(resp.read())
            return result if isinstance(result, dict) else {"kill_active": False}
    except Exception as e:
        log.debug(f"Failed to check network status: {e}")
        return {"kill_active": False}


def kill_switch_monitor(shutdown_callback: Callable[[str], None]):
    """
    Monitor the registry for kill switch activation.
    Runs in a loop, checking every KILL_SWITCH_CHECK_INTERVAL seconds.
    If kill_active is True, verifies the signature (if ADMIN_PUB_PEM is configured)
    and calls shutdown_callback(reason) if valid.
    """
    while True:
        try:
            status = check_network_status()
            if status.get("kill_active", False):
                reason = status.get("reason", "kill switch activated")
                timestamp = status.get("timestamp", "")
                signature = status.get("signature", "")

                # Verify signature if ADMIN_PUB_PEM is configured
                if ADMIN_PUB_PEM:
                    message = f"KILL:{reason}:{timestamp}"
                    if not _ecdsa_verify_signature(ADMIN_PUB_PEM, message.encode(), signature):
                        log.warning(f"Kill switch signature verification failed, ignoring")
                        time.sleep(KILL_SWITCH_CHECK_INTERVAL)
                        continue

                # Signature valid (or no verification configured), execute shutdown
                log.warning(f"Kill switch activated: {reason}")
                shutdown_callback(reason)
                break
        except Exception as e:
            log.error(f"Error in kill switch monitor: {e}")

        time.sleep(KILL_SWITCH_CHECK_INTERVAL)


def start_kill_switch_monitor(shutdown_callback: Callable[[str], None]):
    """Start the kill switch monitor in a daemon thread."""
    t = threading.Thread(
        target=kill_switch_monitor,
        args=(shutdown_callback,),
        daemon=True,
    )
    t.start()
    return t
