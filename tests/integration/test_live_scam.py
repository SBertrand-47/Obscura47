"""The first live economic crime on Obscura: a scam, caught by escrow.

A buyer visits two shops over the real overlay and pays both into escrow. One
seller is honest and delivers; the other takes the money and ships nothing. The
escrow reconciles over two cycles - releasing the honest seller's funds, then
(after a grace cycle) refunding the buyer and banning the scam seller. crossplane
reconstructs the run: the buyer's traffic is observed, the scam seller is flagged
for non-delivery and contained by escrow, and the dashboard narrates the whole
economic story. The economy comes alive on the observed overlay.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_scam.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15701, "node_ws": 15702, "exit": 16700, "exit_ws": 16701,
         "proxy": 19747, "proxy_resp": 19751, "proxy_ws_resp": 19752}
SHOP1, SHOP2 = 18581, 18582   # scam seller's shop, honest seller's shop


def test_scam_is_caught_by_escrow_on_obscura(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    targets = [_overlay.start_http_target(SHOP1),
               _overlay.start_http_target(SHOP2)]
    try:
        from src.range import crossplane, live
        from src.range.report import load_events
        from src.utils import experiment as exp

        eid = "live-scam"
        exp.set_experiment_id(eid)

        def session(actor, sid):
            return live.LiveSession(actor, session_id=sid, experiment_id=eid,
                                    proxy_host="127.0.0.1",
                                    proxy_port=ov["proxy_port"])

        buyer = session("buyer-1", "S-BUYER")
        seller2 = session("seller-2", "S-S2")     # honest
        escrow = live.LiveEscrow("escrow", experiment_id=eid, grace=1)

        # Round 1: buyer shops both stores over the overlay and pays into escrow.
        buyer.visit("127.0.0.1", "/", port=SHOP1)   # the scam seller's shop
        buyer.visit("127.0.0.1", "/", port=SHOP2)   # the honest seller's shop
        buyer.pay("seller-1", 50, "widget")
        buyer.pay("seller-2", 30, "gadget")
        seller2.deliver("buyer-1", "gadget")        # honest seller ships
        first = escrow.settle(load_events(eid))
        # Round 2: scam seller still has not delivered -> refund + ban.
        second = escrow.settle(load_events(eid))

        assert any(s["settle"] == "release" and s["seller"] == "seller-2"
                   for s in first)
        assert any(s["settle"] == "refund" and s["seller"] == "seller-1"
                   for s in second)

        import time
        time.sleep(0.6)
        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"])

        econ = view["economy"]
        assert "seller-1" in econ["scam_sellers"]
        assert econ["scam_sellers"]["seller-1"]["refunded"] is True
        assert econ["volume"] == 80 and econ["refunded"] == 50

        flagged = {f["agent"]: f for f in view["threats"]["flagged_agents"]}
        assert "seller-1" in flagged
        assert flagged["seller-1"]["status"] == "contained"
        assert "escrow" in flagged["seller-1"]["contained_by"]
        assert any("scam" in r for r in flagged["seller-1"]["reasons"])
        # The buyer behaved normally and its shopping was observed on the wire.
        assert "seller-2" not in flagged and "buyer-1" not in flagged
        assert view["sessions"] and any(
            s["session_id"] == "S-BUYER" and s["observed_on_wire"]
            for s in view["sessions"])

        story = " ".join(view["narrative"])
        assert "escrow payment" in story and "seller-1 was flagged" in story
        html = crossplane.render_html(view)
        assert "contained by escrow" in html
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
