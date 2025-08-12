import socket
import threading
import random
import json
import time
import signal
import sys
import base64
from src.core.router import direct_relay_message, build_route47, start_tunnel, send_tunnel_data, close_tunnel
from src.core.discover import broadcast_discovery, listen_for_discovery, observe_discovery
from src.utils.config import (
    PROXY_HOST as CFG_PROXY_HOST,
    PROXY_PORT as CFG_PROXY_PORT,
    PROXY_RESPONSE_PORT as CFG_PROXY_RESPONSE_PORT,
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
PROXY_RESPONSE_PORT = CFG_PROXY_RESPONSE_PORT  # Separate inbound port for exit responses
DISCOVERY_PORT = CFG_DISCOVERY_PORT  # Discovery port for proxies
NODE_DISCOVERY_PORT = CFG_NODE_DISCOVERY_PORT
EXIT_DISCOVERY_PORT = CFG_EXIT_DISCOVERY_PORT
DISCOVERY_INTERVAL = CFG_DISCOVERY_INTERVAL

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
            print(f"🚏 {prefix} exit {destination['host']}:{destination['port']} | no health stats yet")
            return
        ok = stats.get('ok', 0)
        fail = stats.get('fail', 0)
        total = ok + fail
        rtt = stats.get('rtt_ms', float('inf'))
        backoff_left = 0
        if stats.get('backoff_until', 0.0) > time.time():
            backoff_left = int(stats['backoff_until'] - time.time())
        print(f"🚏 {prefix} exit {destination['host']}:{destination['port']} | rtt={rtt:.1f}ms | success={ok}/{total} | backoff={backoff_left}s")
    except Exception:
        pass

pending_requests = {}  # request_id -> client_socket
pending_meta = {}       # request_id -> {'started': ts, 'bytes_up': int, 'bytes_down': int, 'last_activity': ts, 'exit': hostport}
pending_lock = threading.Lock()

def parse_http_request_to_url(request_text: str) -> str | None:
    try:
        lines = request_text.split("\r\n")
        if not lines:
            return None
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 3:
            return None
        method, target, _ = parts[0], parts[1], parts[2]
        if method.upper() == "CONNECT":
            return None  # Not supported yet
        if target.startswith("http://") or target.startswith("https://"):
            return target
        # Otherwise, build from Host header + path
        host = None
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        if not host:
            return None
        path = target if target.startswith("/") else "/"
        return f"http://{host}{path}"
    except Exception:
        return None

def handle_browser_request(client_socket):
    """Handles incoming HTTP requests from the browser."""
    global running
    try:
        if not running:
            return

        request = client_socket.recv(4096)
        if not request:
            return

        print(f"🌍 Received browser request (first 100 chars): {request[:100]}...")

        # Build URL for exit node
        url = parse_http_request_to_url(request.decode(errors="ignore"))
        if not url:
            client_socket.send(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return

        if not relay_peers and not exit_peers:
            print("⚠️ No discovered peers yet. Cannot route request.")
            client_socket.send(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return

        # Choose the best exit destination
        destination = choose_best_exit()
        if not destination and relay_peers:
            candidates = [p for p in relay_peers if p.get("port", 0) >= 6000]
            destination = random.choice(candidates) if candidates else None
        if not destination:
            client_socket.send(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            client_socket.close()
            return

        log_selected_exit("HTTP", destination)

        # Create a unique request id and record the client socket for response
        request_id = str(time.time_ns())
        with pending_lock:
            pending_requests[request_id] = client_socket
            pending_meta[request_id] = {'started': time.time(), 'bytes_up': 0, 'bytes_down': 0}

        return_path = {
            "host": PROXY_HOST,
            "port": PROXY_RESPONSE_PORT,
            "request_id": request_id,
        }

        # Relay URL to exit via random relay route
        direct_relay_message(json.dumps({"data": url}), destination, relay_peers, return_path=return_path, request_id=request_id)
        with pending_lock:
            if request_id in pending_meta:
                pending_meta[request_id]['exit'] = f"{destination['host']}:{destination['port']}"
        print(f"⏳ Waiting for response from the exit node | request_id={request_id}...")

    except ConnectionResetError:
        print("⚠️ Connection reset by client. Ignoring.")
    except Exception as e:
        print(f"❌ Error in handle_browser_request: {e}")
    finally:
        # Do not close here; will close after response or timeout in response handler
        pass

def listen_for_clients():
    """Continuously listens for client discovery responses."""
    print("👂 Listening for client discovery on port 50000...")
    while running:
        try:
            listen_for_discovery(client_peers, local_port=PROXY_PORT, multicast_port=DISCOVERY_PORT)
        except ConnectionResetError:
            print("⚠️ Connection reset during discovery. Retrying...")
            continue
        except Exception as e:
            print(f"❌ Error in client discovery listener: {e}")
            time.sleep(2)  # Prevent infinite error loops

def observe_relays_and_exits():
    """Passively observe relay and exit discovery channels to build peer list."""
    print("👀 Observing relay and exit discovery...")
    # Passive observers now also receive multicast-echoed discovery responses, including pub keys
    threading.Thread(target=observe_discovery, args=(relay_peers, NODE_DISCOVERY_PORT), daemon=True).start()
    threading.Thread(target=observe_discovery, args=(exit_peers, EXIT_DISCOVERY_PORT), daemon=True).start()
    threading.Thread(target=exit_health_monitor, daemon=True).start()
    # Load persisted health if available
    try:
        import json as _json
        from src.utils.config import EXIT_HEALTH_PATH
        with open(EXIT_HEALTH_PATH, 'r', encoding='utf-8') as f:
            data = _json.load(f)
            if isinstance(data, dict):
                for key, val in data.items():
                    if isinstance(key, str) and ':' in key:
                        h, p = key.rsplit(':', 1)
                        try:
                            p = int(p)
                        except Exception:
                            continue
                        exit_health[(h, p)] = val
    except Exception:
        pass

def exit_health_monitor():
    while running:
        try:
            peers = [(p['host'], p['port']) for p in list(exit_peers)]
            for host, port in peers:
                start = time.time()
                ok = False
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(EXIT_CONNECT_TIMEOUT)
                        s.connect((host, port))
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
                        backoff = min(EXIT_FAIL_BACKOFF_BASE * (2 ** (fails - EXIT_BLACKLIST_FAILS)), EXIT_FAIL_BACKOFF_MAX)
                        stats['backoff_until'] = time.time() + backoff
                else:
                    # reset backoff on success
                    stats['backoff_until'] = 0.0
                exit_health[key] = stats
            # Persist health periodically
            try:
                import json as _json
                from src.utils.config import EXIT_HEALTH_PATH
                with open(EXIT_HEALTH_PATH, 'w', encoding='utf-8') as f:
                    _json.dump(exit_health, f)
            except Exception:
                pass
        except Exception as e:
            print(f"⚠️ Exit health monitor error: {e}")
        time.sleep(EXIT_HEALTH_INTERVAL)

def choose_best_exit():
    candidates = [(p['host'], p['port']) for p in list(exit_peers)]
    if not candidates:
        return None
    now = time.time()
    def score(key):
        stats = exit_health.get(key)
        if not stats:
            return (float('inf'), -1)
        # Hard skip if under backoff
        if stats.get('backoff_until', 0.0) > now:
            return (float('inf'), -1)
        total = stats['ok'] + stats['fail']
        success_ratio = (stats['ok'] / total) if total else 0.0
        return (stats['rtt_ms'], -success_ratio)
    best = min(candidates, key=lambda k: score(k))
    return {'host': best[0], 'port': best[1]}

def continuous_discovery():
    """Continuously broadcasts discovery requests so clients/nodes can find the proxy."""
    while running:
        try:
            print("🔍 Broadcasting discovery request for clients...")
            broadcast_discovery(DISCOVERY_PORT)
            # Also trigger node and exit responses (proxy stays passive on those channels)
            broadcast_discovery(NODE_DISCOVERY_PORT)
            broadcast_discovery(EXIT_DISCOVERY_PORT)
            time.sleep(DISCOVERY_INTERVAL)
        except Exception as e:
            print(f"❌ Error broadcasting discovery: {e}")
            time.sleep(2)  # Prevent spamming logs on error

def response_listener():
    """TCP server to receive responses from exit nodes and forward to original client."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((PROXY_HOST, PROXY_RESPONSE_PORT))
        server.listen(5)
        print(f"📥 Proxy response listener on {PROXY_HOST}:{PROXY_RESPONSE_PORT}")

        while running:
            try:
                conn, _ = server.accept()
                threading.Thread(target=handle_exit_response, args=(conn,), daemon=True).start()
            except Exception as e:
                print(f"⚠️ Response listener error: {e}")

def handle_exit_response(conn):
    try:
        data = conn.recv(1024 * 1024)
        if not data:
            return
        packet = json.loads(data.decode())
        typ = packet.get("type")
        request_id = packet.get("request_id", "")
        if JSON_LOGS:
            print(json.dumps({"event":"exit_frame","type":typ,"request_id":request_id}))
        else:
            print(f"📦 Exit frame | type={typ} | request_id={request_id}")

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
                            print(json.dumps({"event":"tunnel_closed","request_id":request_id,"dur_s":round(dur,1),"up":summary.get('bytes_up',0),"down":summary.get('bytes_down',0),"exit":summary.get('exit')}))
                        else:
                            print(f"✅ Tunnel closed | req={request_id} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
                else:
                    # Backwards-compatible HTTP body delivery (non-tunnel)
                    payload = packet.get("data", "")
                    if isinstance(payload, (bytes, bytearray)):
                        client_socket.send(payload)
                    else:
                        body = payload if isinstance(payload, str) else str(payload)
                        if not body.startswith("HTTP/"):
                            headers = (
                                "HTTP/1.1 200 OK\r\n"
                                f"Content-Length: {len(body.encode())}\r\n"
                                "Content-Type: text/html; charset=utf-8\r\n"
                                "Connection: close\r\n\r\n"
                            )
                            client_socket.send(headers.encode() + body.encode())
                        else:
                            client_socket.send(body.encode())
            except Exception as e:
                print(f"❌ Error delivering to client | {e}")
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
                        print(json.dumps({"event":"tunnel_closed_error","request_id":request_id,"dur_s":round(dur,1),"up":summary.get('bytes_up',0),"down":summary.get('bytes_down',0),"exit":summary.get('exit')}))
                    else:
                        print(f"✅ Tunnel closed (error) | req={request_id} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
        else:
            print(f"⚠️ No pending client for request_id={request_id}")
    except Exception as e:
        print(f"❌ Error handling exit response: {e}")
    finally:
        conn.close()

def start_proxy():
    """Starts the proxy server and continuously listens for clients."""
    global running
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    # Start the discovery listener
    threading.Thread(target=listen_for_clients, daemon=True).start()

    # Start continuous discovery broadcasting
    threading.Thread(target=continuous_discovery, daemon=True).start()

    # Passively observe relay and exit announcements
    observe_relays_and_exits()

    # Start response listener for exit node callbacks
    threading.Thread(target=response_listener, daemon=True).start()
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

        print(f"🚀 Proxy running on {PROXY_HOST}:{PROXY_PORT}")

        while running:
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handle_new_client, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except ConnectionResetError:
                print("⚠️ Connection reset while accepting client. Ignoring.")
                continue
            except Exception as e:
                print(f"❌ Error accepting client: {e}")
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
            handle_browser_request(client_socket)
    except Exception as e:
        print(f"❌ Error handling new client: {e}")
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

        return_path = {
            "host": PROXY_HOST,
            "port": PROXY_RESPONSE_PORT,
            "request_id": request_id,
        }

        route = build_route47(relay_peers)
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
                            print(f"⚠️ Tunnel byte cap reached for {request_id}")
                            break
                    send_tunnel_data(destination, route, request_id, base64.b64encode(chunk).decode())
                    with pending_lock:
                        if request_id in pending_meta:
                            pending_meta[request_id]['bytes_up'] += len(chunk)
                            pending_meta[request_id]['last_activity'] = time.time()
                            metrics['bytes_up'] += len(chunk)
                    # Cap by duration
                    if time.time() - started >= max_seconds:
                        print(f"⚠️ Tunnel time cap reached for {request_id}")
                        break
            except Exception as e:
                print(f"⚠️ Upstream error | {e}")
            finally:
                close_tunnel(destination, route, request_id)
        threading.Thread(target=upstream, daemon=True).start()
    except Exception as e:
        print(f"❌ CONNECT handling error: {e}")
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
        print(f"📊 Metrics | active={metrics['active_tunnels']} | total={metrics['total_tunnels']} | up={metrics['bytes_up']}B | down={metrics['bytes_down']}B | frame_retries={r['frame_retries']} | reroutes={r['message_reroutes']}")

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
                    print(f"🧹 Tunnel GC | req={req} | dur={dur:.1f}s | up={summary.get('bytes_up',0)}B | down={summary.get('bytes_down',0)}B | exit={summary.get('exit')}")
            except Exception:
                pass
