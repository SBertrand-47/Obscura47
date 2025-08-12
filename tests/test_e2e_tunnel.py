import socket
import threading
import time


def start_echo_server(host: str = "127.0.0.1", port: int = 18080):
    def _run():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(5)
        while True:
            try:
                c, _ = srv.accept()
                threading.Thread(target=_handle, args=(c,), daemon=True).start()
            except Exception:
                break

    def _handle(conn: socket.socket):
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                conn.sendall(data)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def start_node_and_exit(node_port=5001, exit_port=6000):
    from src.core.node import ObscuraNode
    from src.core.exit_node import ExitNode

    node = ObscuraNode(port=node_port)
    node.run()
    exit_node = ExitNode(port=exit_port)
    threading.Thread(target=exit_node.start_server, daemon=True).start()
    # give them time to bind
    time.sleep(0.5)


def start_proxy_with_injected_peers(node_port=5001, exit_port=6000, proxy_host="127.0.0.1", proxy_port=9047):
    from src.core import proxy as proxy_mod

    # inject peers to avoid relying on multicast in tests
    proxy_mod.relay_peers[:] = [{"host": "127.0.0.1", "port": node_port}]
    proxy_mod.exit_peers[:] = [{"host": "127.0.0.1", "port": exit_port}]

    threading.Thread(target=proxy_mod.start_proxy, daemon=True).start()
    # wait for proxy to start listening
    for _ in range(50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.1)
            s.connect((proxy_host, proxy_port))
            s.close()
            break
        except Exception:
            time.sleep(0.1)


def test_https_connect_echo_through_proxy():
    echo_port = 18080
    start_echo_server(port=echo_port)
    start_node_and_exit()
    start_proxy_with_injected_peers()

    # CONNECT to the echo server via the proxy
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(("127.0.0.1", 9047))
    req = (
        f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n" \
        f"Host: 127.0.0.1:{echo_port}\r\n" \
        "Connection: keep-alive\r\n" \
        "\r\n"
    ).encode()
    s.sendall(req)
    resp = s.recv(4096).decode(errors="ignore")
    assert "200" in resp, f"CONNECT failed: {resp}"

    payload = b"hello obscura47"
    s.sendall(payload)
    echoed = s.recv(len(payload))
    assert echoed == payload, f"Echo mismatch: {echoed!r} != {payload!r}"
    s.close()

