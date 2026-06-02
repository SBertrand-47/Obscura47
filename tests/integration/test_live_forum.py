"""A live forum on Obscura: agents post, a moderator removes abuse, observed.

Two agents visit a forum service over the real overlay and post to it - one a
normal message, one abusive. A moderator reviews the posts and removes the
abusive one, flagging its author. crossplane reconstructs the run: both agents'
traffic is observed on the wire, the forum activity and its moderation are
captured, the abusive author is flagged and contained, and the dashboard
narrates it. Another society service - the social layer - live and observed.

Individual-run integration test (binds sockets). Run with:

    pytest tests/integration/test_live_forum.py -m integration
"""
import os

import pytest

from tests.integration import _overlay

pytestmark = pytest.mark.integration

PORTS = {"node": 15801, "node_ws": 15802, "exit": 16800, "exit_ws": 16801,
         "proxy": 19847, "proxy_resp": 19851, "proxy_ws_resp": 19852}
FORUM_PORT = 18681


def test_forum_abuse_is_moderated_on_obscura(monkeypatch, tmp_path):
    ov = _overlay.bring_up(monkeypatch, tmp_path, PORTS)
    target = _overlay.start_http_target(FORUM_PORT)
    try:
        from src.range import crossplane, live
        from src.range.report import load_events
        from src.utils import experiment as exp

        eid = "live-forum"
        exp.set_experiment_id(eid)

        def session(actor, sid):
            return live.LiveSession(actor, session_id=sid, experiment_id=eid,
                                    proxy_host="127.0.0.1",
                                    proxy_port=ov["proxy_port"])

        user = session("user-1", "S-USER")
        troll = session("troll-1", "S-TROLL")
        moderator = live.LiveModerator("moderator", experiment_id=eid)

        # Both visit the forum over the overlay, then post.
        user.visit("127.0.0.1", "/", port=FORUM_PORT)
        troll.visit("127.0.0.1", "/", port=FORUM_PORT)
        user.post("general", "Hello all, happy to trade fairly here", "p1")
        troll.post("general", "This is a SCAM - click here for free money!",
                   "p2")

        removals = moderator.moderate(load_events(eid))
        assert any(r["author"] == "troll-1" and r["post_id"] == "p2"
                   for r in removals)

        import time
        time.sleep(0.6)
        view = crossplane.correlate(eid, logs_dir=ov["logs_dir"])

        assert view["forum"]["post_count"] == 2
        assert "p2" in view["forum"]["removed"]
        flagged = {f["agent"]: f for f in view["threats"]["flagged_agents"]}
        assert "troll-1" in flagged and "user-1" not in flagged
        assert flagged["troll-1"]["status"] == "contained"
        assert any("abusive" in r for r in flagged["troll-1"]["reasons"])
        # Both posters' visits were observed on the wire.
        on_wire = {s["session_id"] for s in view["sessions"]
                   if s["observed_on_wire"]}
        assert {"S-USER", "S-TROLL"} <= on_wire

        story = " ".join(view["narrative"])
        assert "forum post" in story and "removed for abuse" in story
        html = crossplane.render_html(view)
        assert "troll-1" in html
        out = os.environ.get("OBSCURA_OBSERVE_OUT")
        if out:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(html)
    finally:
        try:
            target.close()
        except Exception:
            pass
