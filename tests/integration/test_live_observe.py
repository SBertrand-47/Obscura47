"""The vision demo, end to end: an agent acts on the REAL overlay and the run is
fully observable across both telemetry planes.

Stands up a loopback overlay (relay + exit + proxy) on high ports, with range
mode + diag enabled and all telemetry routed into a temp dir. A LiveSession then
makes a real request through the overlay under one session id; the request
produces genuine ops-plane trace spans (proxy -> relay -> exit) carrying that
session id, and genuine research-plane dial events. Finally crossplane.correlate
joins them and we assert the session is reconstructed and fully observable - and
that the visual `observe` page renders from this real data.

Excluded from the default run (binds sockets, background threads). Run with:

    pytest tests/integration/test_live_observe.py -m integration
"""
import os
import socket
import threading
import time

import pytest

pytestmark = pytest.mark.integration

NODE_PORT = 15101
NODE_WS_PORT = 15102
EXIT_PORT = 16100
EXIT_WS_PORT = 16101
PROXY_PORT = 19147
PROXY_RESP_PORT = 19151
PROXY_WS_RESP_PORT = 19152
HTTP_PORT = 18181


def _start_http_target(port: int) -> socket.socket:
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


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def test_live_session_is_fully_observable_across_planes(monkeypatch, tmp_path):
    # Env before importing src so config picks up the loopback ports.
    monkeypatch.setenv("OBSCURA_GUARD_PATH", str(tmp_path / "guards.json"))
    monkeypatch.setenv("OBSCURA_NODE_KEY_PATH", str(tmp_path / "node.pem"))
    monkeypatch.setenv("OBSCURA_EXIT_KEY_PATH", str(tmp_path / "exit.pem"))
    monkeypatch.setenv("OBSCURA_REGISTRY_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OBSCURA_DISCOVERY_INTERVAL", "3600")
    monkeypatch.setenv("OBSCURA_PROXY_PORT", str(PROXY_PORT))
    monkeypatch.setenv("OBSCURA_NODE_LISTEN_PORT", str(NODE_PORT))
    monkeypatch.setenv("OBSCURA_EXIT_LISTEN_PORT", str(EXIT_PORT))
    monkeypatch.setenv("OBSCURA_NODE_WS_PORT", str(NODE_WS_PORT))
    monkeypatch.setenv("OBSCURA_EXIT_WS_PORT", str(EXIT_WS_PORT))
    monkeypatch.setenv("OBSCURA_PROXY_WS_RESP_PORT", str(PROXY_WS_RESP_PORT))
    monkeypatch.setenv("OBSCURA_PROXY_RESP_PORT", str(PROXY_RESP_PORT))
    monkeypatch.setenv("OBSCURA_EXIT_DENY_PRIVATE_IPS", "false")
    monkeypatch.setenv("OBSCURA_DIAG", "1")

    from src.core import exit_node as exit_mod
    from src.core import node as node_mod
    from src.core import proxy as proxy_mod
    from src.core.exit_node import ExitNode
    from src.core.node import ObscuraNode
    from src.range import crossplane, live
    from src.utils import config, diag, trace
    from src.utils import experiment as exp

    # Pin ports in each module's namespace directly, so the test is independent
    # of whether config was already imported (with other ports) earlier in the
    # session. The listen ports are passed via constructor; these are the WS /
    # proxy ports read from module globals.
    monkeypatch.setattr(node_mod, "NODE_WS_PORT", NODE_WS_PORT)
    monkeypatch.setattr(exit_mod, "EXIT_WS_PORT", EXIT_WS_PORT)
    monkeypatch.setattr(proxy_mod, "PROXY_PORT", PROXY_PORT)

    # Range mode + isolate both telemetry planes into the temp dir.
    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    logs_dir = str(tmp_path / "logs")
    os.makedirs(logs_dir, exist_ok=True)
    monkeypatch.setattr(diag, "DIAG_DIR", logs_dir)
    monkeypatch.setattr(exp, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(exp, "_current_id", None)
    monkeypatch.setattr(exp, "_env_resolved", False)

    # Isolate discovery so the route uses ONLY our injected loopback peers
    # (no leakage to a dev instance on the LAN).
    noop = lambda *a, **k: None  # noqa: E731
    for mod, name in [(node_mod, "listen_for_discovery"),
                      (node_mod, "broadcast_discovery"),
                      (proxy_mod, "listen_for_discovery"),
                      (proxy_mod, "broadcast_discovery"),
                      (proxy_mod, "observe_discovery"),
                      (proxy_mod, "start_internet_discovery")]:
        monkeypatch.setattr(mod, name, noop)

    assert trace.is_active(), "range + diag must be on for ops spans to emit"

    target = _start_http_target(HTTP_PORT)
    try:
        node = ObscuraNode(port=NODE_PORT)
        node.run()
        exit_node = ExitNode(port=EXIT_PORT, lan_discovery=False)
        threading.Thread(target=exit_node.start_server, daemon=True).start()
        assert _wait_for_port("127.0.0.1", NODE_PORT), "relay never came up"
        assert _wait_for_port("127.0.0.1", EXIT_PORT), "exit never came up"

        now = time.time()
        proxy_mod.relay_peers[:] = [{"host": "127.0.0.1", "port": NODE_PORT,
                                     "pub": node.pub_pem,
                                     "ws_port": NODE_WS_PORT, "ts": now}]
        proxy_mod.exit_peers[:] = [{"host": "127.0.0.1", "port": EXIT_PORT,
                                    "pub": exit_node.pub_pem,
                                    "ws_port": EXIT_WS_PORT, "ts": now}]
        threading.Thread(target=proxy_mod.start_proxy, daemon=True).start()
        assert _wait_for_port("127.0.0.1", PROXY_PORT), "proxy never came up"

        # A real MODEL-DRIVEN agent session on the real overlay. The model is
        # replayed (deterministic, no key); its decisions execute for real.
        from src.range.llm_io import ReplayClient
        eid = "live-observe"
        exp.set_experiment_id(eid)
        sess = live.LiveSession("buyer-1", session_id="S-OBSERVE",
                                experiment_id=eid, proxy_host="127.0.0.1",
                                proxy_port=PROXY_PORT)
        recs = [
            {"blocks": [{"input": {"kind": "visit", "addr": "127.0.0.1",
                                   "path": "/", "port": HTTP_PORT,
                                   "rationale": "inspect the service"},
                         "id": "t1"}],
             "usage": {"input_tokens": 30, "output_tokens": 8}},
            {"blocks": [{"input": {"kind": "finish", "rationale": "done"},
                         "id": "t2"}],
             "usage": {"input_tokens": 20, "output_tokens": 4}},
        ]
        agent = live.LiveAgent("inspect services on Obscura", session=sess,
                               directory=[{"addr": "127.0.0.1",
                                           "port": HTTP_PORT,
                                           "title": "local service"}],
                               client=ReplayClient(recs))
        records = agent.run(max_steps=3)
        assert records[0]["kind"] == "visit", records
        assert "status 200" in (records[0]["result_summary"] or ""), records[0]
        time.sleep(0.7)  # let the terminal span flush to the diag log

        # Join the planes from the REAL emitted telemetry.
        view = crossplane.correlate(eid, logs_dir=logs_dir)
        s = next((x for x in view["sessions"]
                  if x["session_id"] == "S-OBSERVE"), None)
        assert s is not None, f"session not found: {view['coverage']}"
        assert s["made_research_dials"], "no research dial recorded"
        assert s["observed_on_wire"], f"no ops trace: {view['coverage']}"
        # The agent's reasoning is part of the observed session, next to its traffic.
        assert any(e.kind == "agent.decision" for e in s["research_events"]), \
            "agent decision not recorded in the session"
        # The circuit reconstructs the real path proxy -> relay -> exit.
        assert any(c["length"] >= 2 for c in s["circuits"]), \
            f"circuit too short: {[c['length'] for c in s['circuits']]}"
        assert any(sp["event"] == "trace.start"
                   for c in s["circuits"] for sp in c["hops"])

        # The visual view renders from this real data.
        html = crossplane.render_html(view)
        assert "S-OBSERVE" in html and "What the agents did on Obscura" in html
        # Optionally persist the artifact so a human can open it.
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
    finally:
        try:
            target.close()
        except Exception:
            pass
