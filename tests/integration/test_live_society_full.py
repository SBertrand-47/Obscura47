"""The whole live society on Obscura, in one observed run.

Every dimension at once on one real overlay, correlated into one dashboard:

  * security - an attacker fans out across services (recon); a defender bans it.
  * economy  - a buyer pays two sellers via escrow; one delivers, one scams;
               the escrow releases the honest one and refunds + bans the scammer.
  * social   - users post to a forum; a moderator removes an abusive post.
  * memory   - the escrow moves reputation; a reputation gate distrusts the
               negative-standing scammer.

crossplane reconstructs the whole thing - traffic observed on the wire, three
classes of offender flagged and contained by three different controls, the
economy and forum reconstructed, reputation updated - and narrates it as one
"what happened on Obscura" story. The populated society, operating as a system.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_society_full.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15901, "node_ws": 15902, "exit": 16900, "exit_ws": 16901,
         "proxy": 19947, "proxy_resp": 19951, "proxy_ws_resp": 19952}
SHOP1, SHOP2, FORUM = 18781, 18782, 18783   # scam shop, honest shop, forum


def test_full_society_runs_and_is_observed(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    targets = [_overlay.start_http_target(p) for p in (SHOP1, SHOP2, FORUM)]
    try:
        from src.range import crossplane, live
        from src.range.report import load_events
        from src.utils import experiment as exp

        eid = "live-full"
        exp.set_experiment_id(eid)

        def session(actor, sid):
            return live.LiveSession(actor, session_id=sid, experiment_id=eid,
                                    proxy_host="127.0.0.1",
                                    proxy_port=ov["proxy_port"])

        buyer = session("buyer-1", "S-BUYER")
        seller2 = session("seller-2", "S-S2")       # honest
        attacker = session("attacker-1", "S-ATK")
        user = session("user-1", "S-USER")
        troll = session("troll-1", "S-TROLL")

        defender = live.LiveDefender("defender-1", experiment_id=eid)
        escrow = live.LiveEscrow("escrow", experiment_id=eid, grace=1)
        moderator = live.LiveModerator("moderator", experiment_id=eid)
        gate = live.LiveReputationGate("reputation-gate", experiment_id=eid,
                                       threshold=0)

        # --- the society acts (all over the real overlay) ---
        buyer.visit("127.0.0.1", "/", port=SHOP1)
        buyer.visit("127.0.0.1", "/", port=SHOP2)
        buyer.pay("seller-1", 50, "widget")         # to the scam seller
        buyer.pay("seller-2", 30, "gadget")         # to the honest seller
        seller2.deliver("buyer-1", "gadget")
        attacker.visit("127.0.0.1", "/", port=SHOP1)
        attacker.visit("127.0.0.1", "/", port=SHOP2)
        attacker.visit("127.0.0.1", "/", port=FORUM)   # 3 services -> recon
        user.visit("127.0.0.1", "/", port=FORUM)
        troll.visit("127.0.0.1", "/", port=FORUM)
        user.post("general", "Hi all, glad to be trading here", "p1")
        troll.post("general", "SCAM! click here for free money", "p2")

        # --- the controls respond ---
        defender.assess(crossplane.correlate(eid, logs_dir=ov["logs_dir"]))
        moderator.moderate(load_events(eid))
        escrow.settle(load_events(eid))             # release honest, see scam
        escrow.settle(load_events(eid))             # refund + ban the scammer
        gate.enforce(crossplane.correlate(eid, logs_dir=ov["logs_dir"]))

        import time
        time.sleep(0.7)
        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"])

        flagged = {f["agent"]: f for f in view["threats"]["flagged_agents"]}
        # Three classes of offender, each caught by a different control.
        assert flagged["attacker-1"]["status"] == "contained"
        assert any("recon" in r for r in flagged["attacker-1"]["reasons"])
        assert flagged["seller-1"]["status"] == "contained"
        assert any("scam" in r for r in flagged["seller-1"]["reasons"])
        assert flagged["troll-1"]["status"] == "contained"
        assert any("abusive" in r for r in flagged["troll-1"]["reasons"])
        # The honest actors are untouched.
        for good in ("buyer-1", "seller-2", "user-1"):
            assert good not in flagged

        # Each subsystem reconstructed.
        assert view["economy"]["volume"] == 80
        assert "seller-1" in view["economy"]["scam_sellers"]
        assert view["reputation"]["seller-1"] == -2
        assert view["reputation"]["seller-2"] == 1
        assert view["forum"]["post_count"] == 2 and "p2" in view["forum"]["removed"]

        # The narrative tells the whole story.
        story = " ".join(view["narrative"])
        assert "escrow payment" in story and "forum post" in story
        assert "Reputation after settlement" in story

        html = crossplane.render_html(view)
        for token in ("attacker-1", "seller-1", "troll-1", "Reputation",
                      "Traffic graph"):
            assert token in html
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
