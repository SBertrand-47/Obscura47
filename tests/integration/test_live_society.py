"""A live adversarial society with a defender acting DURING the run.

A legit buyer and a fan-out attacker act round by round on a real loopback
overlay while a LiveDefender watches the run and responds in-stream: once the
attacker has probed enough services to trip the recon threshold, the defender
bans it mid-run and its later turns are blocked. crossplane reconstructs the
whole thing and the dashboard shows detection AND response - the attacker
flagged, contained, and stopped, on the cross-agent graph. Detect and respond,
live, from real telemetry.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_society.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15201, "node_ws": 15202, "exit": 16200, "exit_ws": 16201,
         "proxy": 19247, "proxy_resp": 19251, "proxy_ws_resp": 19252}
SERVICES = [18281, 18282, 18283, 18284]   # market, forum, bank, vault


def _visits(*specs):
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


def test_live_defender_bans_recon_attacker_mid_run(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    targets = [_overlay.start_http_target(p) for p in SERVICES]
    try:
        from src.range import crossplane, live
        from src.range.llm_io import ReplayClient
        from src.utils import experiment as exp

        eid = "live-society"
        exp.set_experiment_id(eid)
        directory = [{"addr": "127.0.0.1", "port": p,
                      "title": t} for p, t in
                     zip(SERVICES, ("market", "forum", "bank", "vault"))]

        buyer = live.LiveAgent(
            "buy goods from the market", session=live.LiveSession(
                "buyer-1", session_id="S-BUYER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visits((SERVICES[0], "browse the market"))))
        attacker = live.LiveAgent(
            "find weaknesses anywhere on the network", session=live.LiveSession(
                "attacker-1", session_id="S-ATTACKER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=directory,
            client=ReplayClient(_visits(*[(p, f"probe {p}") for p in SERVICES])))

        defender = live.LiveDefender("defender-1", experiment_id=eid)

        def correlate():
            return crossplane.correlate(eid, logs_dir=ov["logs_dir"])

        transcript = live.run_society(
            [("buyer-1", buyer), ("attacker-1", attacker)],
            defender=defender, correlate=correlate, rounds=6)

        # The defender banned the attacker mid-run (after it tripped recon at the
        # 3rd distinct service), and the attacker's later turns were blocked.
        bans = [t for t in transcript if t.get("banned") == "attacker-1"]
        assert len(bans) == 1, transcript
        assert bans[0]["round"] == 3, transcript
        blocked = [t for t in transcript
                   if t.get("blocked") and t["actor"] == "attacker-1"]
        assert blocked, "attacker was never blocked after the ban"

        view = correlate()
        f = next(x for x in view["threats"]["flagged_agents"]
                 if x["agent"] == "attacker-1")
        assert f["status"] == "contained" and "defender-1" in f["contained_by"]
        assert "buyer-1" not in view["threats"]["flagged"]
        assert "defender-1" in view["graph"]["agents"]
        assert any(r["action"] == "ban" for r in view["graph"]["responses"])

        html = crossplane.render_html(view)
        assert "detect &amp; respond" in html
        assert "contained by defender-1" in html
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(html)
    finally:
        for t in targets:
            try:
                t.close()
            except Exception:
                pass
