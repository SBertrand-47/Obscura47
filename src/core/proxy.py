import socket
import threading
import random
import json
import time
import signal
import sys
import os
import base64
from src.utils.logger import get_logger
from src.core.router import build_route47, start_tunnel, send_tunnel_data, close_tunnel, set_reverse_frame_callback, set_proxy_ws_client
from src.core.discover import broadcast_discovery, listen_for_discovery, observe_discovery
from src.core.internet_discovery import start_internet_discovery, start_kill_switch_monitor
from src.core.encryptions import ecc_load_or_create_keypair, onion_decrypt_with_priv
from src.core.ws_transport import WSClient
from src.utils.config import (
    PROXY_HOST as CFG_PROXY_HOST,
    PROXY_PORT as CFG_PROXY_PORT,
    DISCOVERY_PORT as CFG_DISCOVERY_PORT,
    NODE_DISCOVERY_PORT as CFG_NODE_DISCOVERY_PORT,
    EXIT_DISCOVERY_PORT as CFG_EXIT_DISCOVERY_PORT,
    DISCOVERY_INTERVAL as CFG_DISCOVERY_INTERVAL,
    EXIT_HEALTH_INTERVAL,
    EXIT_CONNECT_TIMEOUT,
    EXIT_BLACKLIST_FAILS,
    EXIT_FAIL_BACKOFF_BASE,
    EXIT_FAIL_BACKOFF_MAX,
    TUNNEL_MAX_SECONDS,
    TUNNEL_MAX_BYTES,
    TUNNEL_IDLE_SECONDS,
    CLEANUP_INTERVAL_SECONDS,
    PROXY_TOKEN,
    MAX_CONCURRENT_TUNNELS,
    MAX_TUNNELS_PER_IP,
    EXIT_HEALTH_DECAY,
    EXIT_HEALTH_RTT_ALPHA,
    JSON_LOGS,
)

PROXY_HOST = CFG_PROXY_HOST
PROXY_PORT = CFG_PROXY_PORT

from src.utils.config import PROXY_KEY_PATH

# Proxy's own ECC keypair — used to decrypt responses routed back through relays
_proxy_priv, _proxy_pub_pem = ecc_load_or_create_keypair(PROXY_KEY_PATH)
DISCOVERY_PORT = CFG_DISCOVERY_PORT  # Discovery port for proxies
NODE_DISCOVERY_PORT = CFG_NODE_DISCOVERY_PORT
EXIT_DISCOVERY_PORT = CFG_EXIT_DISCOVERY_PORT
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL

log = get_logger(__name__)

running = True
relay_peers = []  # Observed relay nodes
exit_peers = []   # Observed exit nodes
client_peers = []  # Observed clients (not used for routing)
exit_health = {}   # (host,port) -> {'rtt_ms': float, 'ok': int, 'fail': int, 'last': float, 'backoff_until': float}
active_tunnels = 0
per_ip_tunnels = {}
metrics = {
    'active_tunnels': 0,
    'total_tunnels': 0,
    'bytes_up': 0,
    'bytes_down': 0,
    'exit_failures': 0,
}

def log_selected_exit(prefix: str, destination: dict):
    try:
        key = (destination['host'], destination['port'])
        stats = exit_health.get(key)
        if not stats:
            log.info(f"{prefix} exit {destination['host']}:{destination['port']} | no health stats yet")
            return
        ok = stats.get('ok', 0)
        fail = stats.get('fail', 0)
        total = ok + fail
        rtt = stats.get('rtt_ms', float('inf'))
        backoff_left = 0
        if stats.get('backoff_until', 0.0) > time.time():
            backoff_left = int(stats['backoff_until'] - time.time())
        log.info(f"{prefix} exit {destination['host']}:{destination['port']} | rtt={rtt:.1f}ms | success={ok}/{total} | backoff={backoff_left}s")
    except Exception:
        pass

pending_requests = {}  # request_id -> client_socket
pending_meta = {}       # request_id -> {'started': ts, 'bytes_up': int, 'bytes_down': int, 'last_activity': ts, 'exit': hostport}
pending_lock = threading.Lock()

def listen_for_clients():
    """Continuously listens for client discovery responses."""
    log.info("Listening for client discovery on port 50000...")
    while running:
        try:
            listen_for_discovery(client_peers, local_port=PROXY_PORT, multicast_port=DISCOVERY_PORT)
        except ConnectionResetError:
            log.warning("Connection reset during discovery. Retrying...")
            continue
        except Exception as e:
            log.error(f"Error in client discovery listener: {e}")
            time.sleep(2)  # Prevent infinite error loops

def observe_relays_and_exits():
    """Passively observe relay and exit discovery channels to build peer list."""
    log.info("Observing relay and exit discovery...")
    # Passive observers now also receive multicast-echoed discovery responses, including pub keys
    threading.Thread(target=observe_discovery, args=(relay_peers, NODE_DISCOVERY_PORT), daemon=True).start()
    threading.Thread(target=observe_discovery, args=(exit_peers, EXIT_DISCOVERY_PORT), daemon=True).start()
    threading.Thread(target=exit_health_monitor, daemon=True).start()

def exit_health_monitor():
    while running:
        try:
            peers = [(p['host'], p['port']) for p in list(exit_peers)]
            for host, port in peers:
                start = time.time()
                ok = False
                try:
                    with socket.create_connection((host, port), timeout=EXIT_CONNECT_TIMEOUT) as s:
                        ok = True
                except Exception:
                    ok = False
                rtt_ms = (time.time() - start) * 1000.0
                key = (host, port)
                stats = exit_health.get(key, {'rtt_ms': float('inf'), 'ok': 0, 'fail': 0, 'last': 0.0, 'backoff_until': 0.0})
                if ok:
                    prev = stats['rtt_ms'] if stats['rtt_ms'] != float('inf') else rtt_ms
                    stats['rtt_ms'] = (EXIT_HEALTH_RTT_ALPHA * rtt_ms) + ((1 - EXIT_HEALTH_RTT_ALPHA) * prev)
                stats['ok'] = stats.get('ok', 0) + (1 if ok else 0)
                stats['fail'] = stats.get('fail', 0) + (0 if ok else 1)
                stats['last'] = time.time()
                # Backoff calculation on failure
                if not ok:
                    fails = stats['fail']
                    if fails >= EXIT_BLACKLIST_FAILS:
                        # exponential backoff capping
                        exp = min(fails - EXIT_BLACKLIST_FAILS, 20)  # cap exponent to avoid int-too-large overflow
                        backoff = min(EXIT_FAIL_BACKOFF_BASE * (2 ** exp), EXIT_FAIL_BACKOFF_MAX)
                        stats['backoff_until'] = time.time() + backoff
                else:
                    # reset backoff on success
                    stats['backoff_until'] = 0.0
                exit_health[key] = stats
        except Exception as e:
            log.warning(f"Exit health monitor error: {e}")
        time.sleep(EXIT_HEALTH_INTERVAL)

def choose_best_exit():
    now = time.time()
    candidates = [(p['host'], p['port']) for p in list(exit_peers)]
    if not candidates:
        return None
    def score(key):
        stats = exit_health.get(key)
        if not stats:
            return (0.0, 0.0)  # unseen — prefer over known-bad exits
        if stats.get('backoff_until', 0.0) > now:
            return None  # in backoff, exclude
        total = stats['ok'] + stats['fail']
        success_ratio = (stats['ok'] / total) if total else 0.0
        return (stats['rtt_ms'], -success_ratio)
    # Drop exits that are currently in backoff
    available = [k for k in candidates if score(k) is not None]
    if not available:
        return None
    best = min(available, key=lambda k: score(k))
    # Return the full peer dict so downstream hops have pub, ws_port, etc.
    for p in exit_peers:
        if p['host'] == best[0] and p['port'] == best[1]:
            return dict(p)
    return {'host': best[0], 'port': best[1]}

def continuous_discovery():
    """Continuously broadcasts discovery requests so clients/nodes can find the proxy."""
    while running:
        try:
            log.info("Broadcasting discovery request for clients...")
            broadcast_discovery(DISCOVERY_PORT)
            # Also trigger node and exit responses (proxy stays passive on those channels)
            broadcast_discovery(NODE_DISCOVERY_PORT)
            broadcast_discovery(EXIT_DISCOVERY_PORT)
            time.sleep(DISCOVERY_INTERVAL)
        except Exception as e:
            log.error(f"Error broadcasting discovery: {e}")
            time.sleep(2)  # Prevent spamming logs on error

def _handle_exit_response_data(raw_data):
    """Shared handler for exit response frames (used by both TCP and WS listeners)."""
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode()
    packet = json.loads(raw_data)
    typ = packet.get("type")
    request_id = packet.get("request_id", "")
    if JSON_LOGS:
        log.debug(json.dumps({"event":"exit_frame","type":typ,"request_id":request_id}))
    else:
        log.debug(f"Exit frame | type={typ} | request_id={request_id}")

    with pending_lock:
        client_socket = pending_requests.get(request_id)
        meta = pending_meta.get(request_id, {'bytes_up': 0, 'bytes_down': 0, 'started': time.time(), 'last_activity': time.time(), 'exit': None})

    if client_socket:
        try:
            if typ == "data":
                chunk_b64 = packet.get("chunk", "")
                if chunk_b64:
                    decoded = base64.b64decode(chunk_b64)
                    client_socket.sendall(decoded)
                    meta['bytes_down'] += len(decoded)
                    meta['last_activity'] = time.time()
                    metrics['bytes_down'] += len(decoded)
            elif typ == "close":
                try:
                    client_socket.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                client_socket.close()
                with pending_lock:
                    summary = pending_meta.pop(request_id, None)
                    pending_requests.pop(request_id, None)
                if summary:
                    dur = max(0.0, time.time() - summary.get('started', time.time()))
                    if JSON_LOGS:
                        log.info(json.dumps({"event":"tunnel_closed","request_id":request_id,"dur_s":round(dur,1),"up":summary.get('bytes_up',0),"down":summary.get('bytes_down',0),"exit":summary.get('exit')}))
                    else:
                        log.info(f"Tunnel closed | req={request_id} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
            else:
                log.warning(f"Unknown tunnel frame type: {typ} | request_id={request_id}")
        except Exception as e:
            log.error(f"Error delivering to client | {e}")
            try:
                client_socket.close()
            except Exception:
                pass
            with pending_lock:
                summary = pending_meta.pop(request_id, None)
                pending_requests.pop(request_id, None)
            if summary:
                dur = max(0.0, time.time() - summary.get('started', time.time()))
                if JSON_LOGS:
                    log.error(json.dumps({"event":"tunnel_closed_error","request_id":request_id,"dur_s":round(dur,1),"up":summary.get('bytes_up',0),"down":summary.get('bytes_down',0),"exit":summary.get('exit')}))
                else:
                    log.error(f"Tunnel closed (error) | req={request_id} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
    else:
        log.warning(f"No pending client for request_id={request_id}")


def _handle_reverse_response(frame: dict):
    """Process a reverse-channel response frame from an outbound tunnel socket.

    The frame's ``encrypted_response`` is decrypted with the proxy's private
    key and then dispatched through the normal response handler.  This is the
    primary path when the proxy is behind NAT — responses flow back on the
    same TCP/WS connections used to send requests, so no new inbound
    connections to the proxy are needed.
    """
    req_id = frame.get('request_id', '')
    encrypted = frame.get('encrypted_response')
    if encrypted:
        decrypted = onion_decrypt_with_priv(_proxy_priv, encrypted)
        if decrypted:
            try:
                _handle_exit_response_data(decrypted)
            except Exception as e:
                log.error(f"Reverse response processing error | request_id={req_id} | {e}")
            return
        log.warning(f"Could not decrypt reverse response | request_id={req_id}")
        return
    log.warning(f"No encrypted_response in reverse frame | request_id={req_id}")


def _proxy_ws_on_receive(message):
    """WSClient on_receive adapter for the proxy.

    Incoming reverse-channel frames arrive as JSON strings on the proxy's
    outbound WebSocket connections.  Parse them and hand off to the
    existing dict-based reverse-frame handler.
    """
    try:
        frame = json.loads(message) if isinstance(message, str) else message
    except Exception as e:
        log.error(f"Proxy WS on_receive parse error: {e}")
        return
    if not isinstance(frame, dict):
        return
    if frame.get('type') in ('reverse_data', 'reverse_close'):
        try:
            _handle_reverse_response(frame)
        except Exception as e:
            log.error(f"Proxy reverse handler error: {e}")


_proxy_ws_client_instance = None


def _init_proxy_ws_client():
    """Create the proxy's own WSClient and register it for outbound sends.

    Each role owns its own WSClient so that reverse-channel frames arriving
    on this role's outbound WebSocket connections are processed by this
    role's handler.  Sharing a process-wide singleton across roles lets one
    role's handler intercept frames meant for another.
    """
    global _proxy_ws_client_instance
    if _proxy_ws_client_instance is not None:
        return _proxy_ws_client_instance
    from src.utils.config import (
        CHANNEL_QUEUE_MAX, CHANNEL_IDLE_CLOSE_SECONDS, TLS_VERIFY,
    )
    _proxy_ws_client_instance = WSClient(
        _proxy_priv, _proxy_pub_pem,
        queue_max=CHANNEL_QUEUE_MAX,
        idle_close_seconds=CHANNEL_IDLE_CLOSE_SECONDS,
        tls_verify=TLS_VERIFY,
        on_receive=_proxy_ws_on_receive,
    )
    set_proxy_ws_client(_proxy_ws_client_instance)
    return _proxy_ws_client_instance


def start_proxy():
    """Starts the proxy server and continuously listens for clients."""
    global running
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    # Own WSClient (identity + reverse-channel handler) for outbound WS sends.
    _init_proxy_ws_client()

    # Register reverse-channel callback so responses arriving on outbound
    # tunnel sockets are decrypted and delivered to the pending client.
    set_reverse_frame_callback(_handle_reverse_response)

    # Initialize guard node set (first-hop pinning). No-op when disabled.
    from src.core.guards import init_guards
    guards = init_guards()
    if guards is not None:
        snap = guards.snapshot()
        if snap:
            log.info(f"[guards] Loaded {len(snap)} pinned guard(s) from disk")
        else:
            log.info("[guards] No persisted guards; will pin from peer pool on first circuit")

    # Start the discovery listener
    threading.Thread(target=listen_for_clients, daemon=True).start()

    # Start continuous discovery broadcasting
    threading.Thread(target=continuous_discovery, daemon=True).start()

    # Passively observe relay and exit announcements
    observe_relays_and_exits()

    # Internet-wide peer discovery via bootstrap registry
    start_internet_discovery(relay_peers, exit_peers)

    # Kill switch monitor for proxy shutdown
    def _proxy_shutdown(reason: str):
        global running
        running = False
        log.warning(f"Kill switch activated: {reason}")
        sys.exit(0)

    start_kill_switch_monitor(_proxy_shutdown)

    threading.Thread(target=metrics_worker, daemon=True).start()
    threading.Thread(target=cleanup_worker, daemon=True).start()
    # Start channel idle sweeper in router
    try:
        from src.core.router import channel_idle_sweeper
        threading.Thread(target=channel_idle_sweeper, daemon=True).start()
    except Exception:
        pass

    # Start proxy server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # Keep socket alive
        server.bind((PROXY_HOST, PROXY_PORT))
        server.listen(5)

        log.info(f"Proxy running on {PROXY_HOST}:{PROXY_PORT}")

        while running:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handle_new_client, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except ConnectionResetError:
                log.warning("Connection reset while accepting client. Ignoring.")
                continue
            except Exception as e:
                log.error(f"Error accepting client: {e}")
                continue

def handle_new_client(client_socket):
    try:
        global active_tunnels
        # Token check if configured
        if PROXY_TOKEN:
            peek = client_socket.recv(2048, socket.MSG_PEEK)
            text = peek.decode(errors="ignore")
            if f"Proxy-Token: {PROXY_TOKEN}" not in text:
                client_socket.send(b"HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n")
                client_socket.close()
                return
        # Limit concurrent tunnels
        if active_tunnels >= MAX_CONCURRENT_TUNNELS:
            client_socket.send(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return
        # Per-IP limit
        try:
            peer_ip = client_socket.getpeername()[0]
        except Exception:
            peer_ip = "0.0.0.0"
        count = per_ip_tunnels.get(peer_ip, 0)
        if count >= MAX_TUNNELS_PER_IP:
            client_socket.send(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return
        peek = client_socket.recv(1024, socket.MSG_PEEK)
        if not peek:
            client_socket.close()
            return
        first_line = peek.decode(errors="ignore").split("\r\n", 1)[0]
        if first_line.upper().startswith("CONNECT "):
            active_tunnels += 1
            metrics['active_tunnels'] = active_tunnels
            metrics['total_tunnels'] += 1
            per_ip_tunnels[peer_ip] = per_ip_tunnels.get(peer_ip, 0) + 1
            try:
                handle_connect(client_socket)
            finally:
                active_tunnels -= 1
                metrics['active_tunnels'] = active_tunnels
                per_ip_tunnels[peer_ip] = max(0, per_ip_tunnels.get(peer_ip, 1) - 1)
        else:
            # Only CONNECT tunnels are supported (no legacy HTTP relay)
            client_socket.send(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
            client_socket.close()
    except Exception as e:
        log.error(f"Error handling new client: {e}")
        try:
            client_socket.close()
        except Exception:
            pass

def handle_connect(client_socket):
    try:
        data = client_socket.recv(4096).decode(errors="ignore")
        request_line = data.split("\r\n", 1)[0]
        _, target, _ = request_line.split()
        host, port_str = target.split(":")
        port = int(port_str)

        if not relay_peers and not exit_peers:
            client_socket.send(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return

        destination = choose_best_exit()
        if not destination:
            client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return

        log_selected_exit("CONNECT", destination)

        request_id = str(time.time_ns())
        with pending_lock:
            pending_requests[request_id] = client_socket

        route = build_route47(relay_peers)
        # Reverse channel: responses flow back on the same connections,
        # so return_path only needs the proxy's public key for encryption.
        return_path = {
            "pub": _proxy_pub_pem,
            "request_id": request_id,
        }

        start_tunnel(destination, relay_peers, request_id, host, port, return_path, route=route)
        started = time.time()
        max_seconds = TUNNEL_MAX_SECONDS
        with pending_lock:
            if request_id in pending_meta:
                pending_meta[request_id]['exit'] = f"{destination['host']}:{destination['port']}"

        # Immediately acknowledge to the client; the exit will attempt to connect
        client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Stream client bytes to exit via tunnel
        def upstream():
            try:
                while True:
                    chunk = client_socket.recv(8192)
                    if not chunk:
                        break
                    # Cap by total bytes
                    with pending_lock:
                        meta = pending_meta.get(request_id)
                        if meta and meta['bytes_up'] + meta['bytes_down'] >= TUNNEL_MAX_BYTES:
                            log.warning(f"Tunnel byte cap reached for {request_id}")
                            break
                    send_tunnel_data(destination, route, request_id, base64.b64encode(chunk).decode())
                    with pending_lock:
                        if request_id in pending_meta:
                            pending_meta[request_id]['bytes_up'] += len(chunk)
                            pending_meta[request_id]['last_activity'] = time.time()
                            metrics['bytes_up'] += len(chunk)
                    # Cap by duration
                    if time.time() - started >= max_seconds:
                        log.warning(f"Tunnel time cap reached for {request_id}")
                        break
            except Exception as e:
                log.warning(f"Upstream error | {e}")
            finally:
                close_tunnel(destination, route, request_id)
        threading.Thread(target=upstream, daemon=True).start()
    except Exception as e:
        log.error(f"CONNECT handling error: {e}")
        try:
            client_socket.close()
        except Exception:
            pass

if __name__ == "__main__":
    start_proxy()

def metrics_worker():
    while running:
        time.sleep(10)
        try:
            from src.core.router import get_router_metrics
            r = get_router_metrics()
        except Exception:
            r = {'frame_retries': 0, 'message_reroutes': 0}
        log.info(f"Metrics | active={metrics['active_tunnels']} | total={metrics['total_tunnels']} | up={metrics['bytes_up']}B | down={metrics['bytes_down']}B | frame_retries={r['frame_retries']}")

def cleanup_worker():
    while running:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        now = time.time()
        stale = []
        with pending_lock:
            for req_id, meta in list(pending_meta.items()):
                idle = now - meta.get('last_activity', meta.get('started', now))
                dur = now - meta.get('started', now)
                if idle >= TUNNEL_IDLE_SECONDS or dur >= TUNNEL_MAX_SECONDS or (meta.get('bytes_up',0) + meta.get('bytes_down',0)) >= TUNNEL_MAX_BYTES:
                    stale.append(req_id)
        for req in stale:
            try:
                with pending_lock:
                    client = pending_requests.pop(req, None)
                    summary = pending_meta.pop(req, None)
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass
                if summary:
                    dur = max(0.0, now - summary.get('started', now))
                    log.info(f"Tunnel GC | req={req} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
            except Exception:
                pass
