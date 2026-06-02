"""An adversarial multi-agent society on the real overlay, observed and flagged.

A legitimate buyer visits one service; an attacker fans out across several
services (recon). Both run model-driven (replayed for determinism) on a real
loopback overlay. crossplane reconstructs the whole run, builds the cross-agent
traffic graph, and the threat heuristic flags the attacker's fan-out - so the
observe dashboard shows the attack pattern caught, not just raw traffic. This is
the "dark web for agents" populated, watched, and triaged.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_society.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15201, "node_ws": 15202, "exit": 16200, "exit_ws": 16201,
         "proxy": 19247, "proxy_resp": 19251, "proxy_ws_resp": 19252}
SERVICES = [18281, 18282, 18283]   # market, forum, bank


def _visits(*specs):
    """Build a replay recording: one visit per (port, rationale), then finish."""
    recs = []
    for i, (port, why) in enumerate(specs):
        recs.append({"blocks": [{"input": {"kind": "visit", "addr": "127.0.0.1",
                                           "path": "/", "port": port,
                                           "rationale": why},
                                 "id": f"v{i}"}],
                     "usage": {"input_tokens": 30, "output_tokens": 8}})
    recs.append({"blocks": [{"input": {"kind": "finish", "rationale": "done"},
                             "id": "fin"}],
                 "usage": {"input_tokens": 20, "output_tokens": 4}})
    return recs


def test_adversarial_society_flags_recon_on_the_graph(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    targets = [_overlay.start_http_target(p) for p in SERVICES]
    try:
        from src.range import crossplane, live
        from src.range.llm_io import ReplayClient
        from src.utils import experiment as exp

        eid = "live-society"
        exp.set_experiment_id(eid)
        directory = [{"addr": "127.0.0.1", "port": p, "title": t}
                     for p, t in zip(SERVICES, ("market", "forum", "bank"))]

        # Legit buyer: one service.
        buyer = live.LiveAgent(
            "buy goods from the market", session=live.LiveSession(
                "buyer-1", session_id="S-BUYER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visits((SERVICES[0], "browse the market"))))
        # Attacker: fans out across every service (recon).
        attacker = live.LiveAgent(
            "find weaknesses anywhere on the network", session=live.LiveSession(
                "attacker-1", session_id="S-ATTACKER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visits(
                (SERVICES[0], "probe the market"),
                (SERVICES[1], "probe the forum"),
                (SERVICES[2], "probe the bank"))))

        buyer.run(max_steps=3)
        attacker.run(max_steps=5)
        import time
        time.sleep(0.8)

        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"])
        sessions = {s["session_id"]: s for s in view["sessions"]}
        assert {"S-BUYER", "S-ATTACKER"} <= set(sessions)
        assert all(sessions[k]["observed_on_wire"] for k in sessions), \
            view["coverage"]

        # The graph shows the attacker's fan-out (3 services) vs the buyer (1).
        g = view["graph"]
        atk_edges = [e for e in g["edges"] if e["src"] == "attacker-1"]
        buy_edges = [e for e in g["edges"] if e["src"] == "buyer-1"]
        assert len(atk_edges) == 3, atk_edges
        assert len(buy_edges) == 1, buy_edges

        # The threat heuristic flags the attacker (recon), not the buyer.
        flagged = view["threats"]["flagged"]
        assert "attacker-1" in flagged
        assert "buyer-1" not in flagged

        # A live defender watches the run and RESPONDS: flags + bans the
        # attacker. Its response is real research telemetry under the same run.
        defender = live.LiveDefender("defender-1", experiment_id=eid)
        issued = defender.assess(view)
        assert any(r["target"] == "attacker-1" and r["action"] == "ban"
                   for r in issued)
        time.sleep(0.3)

        # Re-correlate: the attacker is now flagged AND contained.
        view2 = crossplane.correlate(eid, logs_dir=ov["logs_dir"])
        f = next(x for x in view2["threats"]["flagged_agents"]
                 if x["agent"] == "attacker-1")
        assert f["status"] == "contained"
        assert "defender-1" in f["contained_by"]
        assert "defender-1" in view2["graph"]["agents"]
        assert any(r["action"] == "ban" for r in view2["graph"]["responses"])

        # The dashboard shows detection AND response.
        html = crossplane.render_html(view2)
        assert "<svg" in html and "detect &amp; respond" in html
        assert "contained by defender-1" in html
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
    finally:
        for t in targets:
            try:
                t.close()
            except Exception:
                pass
