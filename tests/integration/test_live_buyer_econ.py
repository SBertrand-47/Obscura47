"""Replay of a REAL Claude buyer making autonomous purchases on Obscura.

A real claude-sonnet-4-6 buyer was run on a live overlay: it inspected a market,
confirmed a listing, and paid a seller into escrow for goods. Its decisions are
captured in tests/fixtures/real_runs/live_buyer_econ_sonnet.json. This replays
them through a LiveAgent over a real loopback overlay (deterministic, no key):
the real buyer's payment goes to a scam seller who never delivers, and the
escrow refunds the buyer and bans the seller. The permanent record that a real
autonomous model traded in the live economy - and was protected when scammed.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_buyer_econ.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 16101, "node_ws": 16102, "exit": 17100, "exit_ws": 17101,
         "proxy": 19147, "proxy_resp": 19151, "proxy_ws_resp": 19152}
SHOP = 18881
_FIX = os.path.join(os.path.dirname(__file__), os.pardir, "fixtures",
                    "real_runs")


def test_real_buyer_pays_and_is_protected_from_a_scam(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    target = _overlay.start_http_target(SHOP)
    try:
        from src.range import crossplane, live
        from src.range.llm_io import ReplayClient, load_recording
        from src.range.report import load_events
        from src.utils import experiment as exp

        eid = "buyer-econ"
        exp.set_experiment_id(eid)
        recs = load_recording(os.path.join(_FIX, "live_buyer_econ_sonnet.json"))
        buyer = live.LiveAgent(
            "buy goods", session=live.LiveSession(
                "buyer-1", session_id="S-BUYER", experiment_id=eid,
                proxy_host="127.0.0.1", proxy_port=ov["proxy_port"]),
            directory=[{"addr": "127.0.0.1", "port": SHOP, "title": "market",
                        "seller": "seller-1", "item": "premium widget",
                        "price": 50}],
            client=ReplayClient(recs))
        escrow = live.LiveEscrow("escrow", experiment_id=eid, grace=1)

        records = buyer.run(max_steps=4)
        # The real buyer inspected the market then paid into escrow.
        assert any(r["kind"] == "pay" for r in records)
        pay = next(r for r in records if r["kind"] == "pay")
        assert "seller-1" in pay["result_summary"]

        # The scam seller never delivers; escrow reconciles over two cycles.
        escrow.settle(load_events(eid))
        escrow.settle(load_events(eid))

        import time
        time.sleep(0.6)
        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"])

        # The buyer was protected: payment refunded, scammer flagged + contained.
        assert view["economy"]["payments"][0]["status"] == "refunded"
        assert "seller-1" in view["economy"]["scam_sellers"]
        flagged = {f["agent"]: f for f in view["threats"]["flagged_agents"]}
        assert flagged["seller-1"]["status"] == "contained"
        assert any("scam" in r for r in flagged["seller-1"]["reasons"])
        assert "buyer-1" not in flagged
        assert view["reputation"]["seller-1"] == -2
        # The buyer's shopping traffic was observed on the wire.
        assert any(s["session_id"] == "S-BUYER" and s["observed_on_wire"]
                   for s in view["sessions"])

        story = " ".join(view["narrative"])
        assert "escrow payment" in story
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(crossplane.render_html(view))
    finally:
        try:
            target.close()
        except Exception:
            pass
