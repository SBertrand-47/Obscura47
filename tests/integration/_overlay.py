"""Reusable in-process loopback overlay for integration tests.

Stands up a relay + exit + proxy on caller-chosen high ports with range mode +
diag on and all telemetry routed into a temp dir, with discovery stubbed so the
route uses ONLY the injected loopback peers (no leakage to a dev instance on the
LAN). Not collected by pytest (no test_ prefix); imported by integration tests.
"""
import os
import socket
import threading
import time


def start_http_target(port: int) -> socket.socket:
    """A trivial HTTP/1.1 responder: any request gets a 200 with a tiny body."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(5)

    def _accept():
        while True:
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=_serve, args=(conn,), daemon=True).start()

    def _serve(conn):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            body = b"ok"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                         + str(len(body)).encode()
                         + b"\r\nConnection: close\r\n\r\n" + body)
        except Exception:
            pass
        finally:
            conn.close()

    threading.Thread(target=_accept, daemon=True).start()
    return srv


def wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def bring_up(monkeypatch, tmp_path, ports: dict) -> dict:
    """Bring up the loopback overlay. Returns {proxy_port, logs_dir, node, exit}.

    ``ports`` keys: node, node_ws, exit, exit_ws, proxy, proxy_resp,
    proxy_ws_resp. Caller is responsible for setting an experiment id and
    driving traffic; this only stands up the network and isolates telemetry.
    """
    for env, key in [("OBSCURA_PROXY_PORT", "proxy"),
                     ("OBSCURA_NODE_LISTEN_PORT", "node"),
                     ("OBSCURA_EXIT_LISTEN_PORT", "exit"),
                     ("OBSCURA_NODE_WS_PORT", "node_ws"),
                     ("OBSCURA_EXIT_WS_PORT", "exit_ws"),
                     ("OBSCURA_PROXY_WS_RESP_PORT", "proxy_ws_resp"),
                     ("OBSCURA_PROXY_RESP_PORT", "proxy_resp")]:
        monkeypatch.setenv(env, str(ports[key]))
    monkeypatch.setenv("OBSCURA_GUARD_PATH", str(tmp_path / "guards.json"))
    monkeypatch.setenv("OBSCURA_NODE_KEY_PATH", str(tmp_path / "node.pem"))
    monkeypatch.setenv("OBSCURA_EXIT_KEY_PATH", str(tmp_path / "exit.pem"))
    monkeypatch.setenv("OBSCURA_REGISTRY_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OBSCURA_DISCOVERY_INTERVAL", "3600")
    monkeypatch.setenv("OBSCURA_EXIT_DENY_PRIVATE_IPS", "false")
    monkeypatch.setenv("OBSCURA_DIAG", "1")

    from src.core import exit_node as exit_mod
    from src.core import node as node_mod
    from src.core import proxy as proxy_mod
    from src.core.exit_node import ExitNode
    from src.core.node import ObscuraNode
    from src.utils import config, diag
    from src.utils import experiment as exp

    # Pin ports in each module's namespace so this is independent of config
    # import order.
    monkeypatch.setattr(node_mod, "NODE_WS_PORT", ports["node_ws"])
    monkeypatch.setattr(exit_mod, "EXIT_WS_PORT", ports["exit_ws"])
    monkeypatch.setattr(proxy_mod, "PROXY_PORT", ports["proxy"])

    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    logs_dir = str(tmp_path / "logs")
    os.makedirs(logs_dir, exist_ok=True)
    monkeypatch.setattr(diag, "DIAG_DIR", logs_dir)
    monkeypatch.setattr(exp, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(exp, "_current_id", None)
    monkeypatch.setattr(exp, "_env_resolved", False)

    noop = lambda *a, **k: None  # noqa: E731
    for mod, name in [(node_mod, "listen_for_discovery"),
                      (node_mod, "broadcast_discovery"),
                      (proxy_mod, "listen_for_discovery"),
                      (proxy_mod, "broadcast_discovery"),
                      (proxy_mod, "observe_discovery"),
                      (proxy_mod, "start_internet_discovery")]:
        monkeypatch.setattr(mod, name, noop)

    node = ObscuraNode(port=ports["node"])
    node.run()
    exit_node = ExitNode(port=ports["exit"], lan_discovery=False)
    threading.Thread(target=exit_node.start_server, daemon=True).start()
    assert wait_for_port("127.0.0.1", ports["node"]), "relay never came up"
    assert wait_for_port("127.0.0.1", ports["exit"]), "exit never came up"

    now = time.time()
    proxy_mod.relay_peers[:] = [{"host": "127.0.0.1", "port": ports["node"],
                                 "pub": node.pub_pem,
                                 "ws_port": ports["node_ws"], "ts": now}]
    proxy_mod.exit_peers[:] = [{"host": "127.0.0.1", "port": ports["exit"],
                                "pub": exit_node.pub_pem,
                                "ws_port": ports["exit_ws"], "ts": now}]
    threading.Thread(target=proxy_mod.start_proxy, daemon=True).start()
    assert wait_for_port("127.0.0.1", ports["proxy"]), "proxy never came up"

    return {"proxy_port": ports["proxy"], "logs_dir": logs_dir,
            "node": node, "exit": exit_node}
