"""A multi-agent live society on the real overlay, observed as one graph.

Two model-driven agents (a buyer and an attacker, both replayed for
determinism) act on a real loopback overlay against a shared service. Their
reasoning, their dials, and the circuits their traffic produced are all
captured; crossplane then reconstructs the whole run and builds the cross-agent
traffic graph - who dialed whom - from this real telemetry. This is the "dark
web for agents" populated and watched, not a single dial.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_society.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15201, "node_ws": 15202, "exit": 16200, "exit_ws": 16201,
         "proxy": 19247, "proxy_resp": 19251, "proxy_ws_resp": 19252}
SERVICE_PORT = 18281


def _visit_then_finish(port, rationale):
    return [
        {"blocks": [{"input": {"kind": "visit", "addr": "127.0.0.1",
                               "path": "/", "port": port,
                               "rationale": rationale}, "id": "t1"}],
         "usage": {"input_tokens": 30, "output_tokens": 8}},
        {"blocks": [{"input": {"kind": "finish", "rationale": "done"},
                     "id": "t2"}],
         "usage": {"input_tokens": 20, "output_tokens": 4}},
    ]


def test_multi_agent_society_is_observable_as_a_graph(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    target = _overlay.start_http_target(SERVICE_PORT)
    try:
        from src.range import crossplane, live
        from src.range.llm_io import ReplayClient
        from src.utils import experiment as exp

        eid = "live-society"
        exp.set_experiment_id(eid)
        directory = [{"addr": "127.0.0.1", "port": SERVICE_PORT,
                      "title": "seller-1's market"}]

        # Two model-driven agents acting on the same overlay, same experiment.
        buyer = live.LiveAgent(
            "buy goods from the market", session=live.LiveSession(
                "buyer-1", session_id="S-BUYER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visit_then_finish(SERVICE_PORT, "browse deals")))
        attacker = live.LiveAgent(
            "probe the market for weaknesses", session=live.LiveSession(
                "attacker-1", session_id="S-ATTACKER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visit_then_finish(SERVICE_PORT, "recon")))

        assert buyer.run(max_steps=3)[0]["result_summary"].startswith("status 200")
        assert attacker.run(max_steps=3)[0]["result_summary"].startswith("status 200")

        import time
        time.sleep(0.7)  # let terminal spans flush

        # Both agents and their real traffic are reconstructed; the service maps
        # to its hosting agent so the graph is the social graph of the run.
        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"],
                                    hosts={"127.0.0.1": "seller-1"})
        sessions = {s["session_id"]: s for s in view["sessions"]}
        assert {"S-BUYER", "S-ATTACKER"} <= set(sessions)
        assert sessions["S-BUYER"]["observed_on_wire"]
        assert sessions["S-ATTACKER"]["observed_on_wire"]

        g = view["graph"]
        assert set(g["agents"]) == {"buyer-1", "attacker-1"}
        edges = {(e["src"], e["dst_agent"]) for e in g["edges"]}
        # Both agents transacted with seller-1, observed on the wire.
        assert ("buyer-1", "seller-1") in edges
        assert ("attacker-1", "seller-1") in edges
        assert all(e["observed"] for e in g["edges"])

        # The whole society renders to one observable page.
        html = crossplane.render_html(view)
        assert "Traffic graph" in html
        assert "buyer-1" in html and "attacker-1" in html
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
    finally:
        try:
            target.close()
        except Exception:
            pass
