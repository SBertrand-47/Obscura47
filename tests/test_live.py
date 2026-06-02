"""Tests for the live bridge (src/range/live.py) and end-to-end cross-plane
correlation on telemetry from the REAL emission code paths.

Two angles:
* LiveSession against a loopback fake proxy: proves it threads the session id
  into X-Obscura-Session and emits research events with that id (no overlay).
* Real trace.py spans + real observatory events under range mode + diag, joined
  by src.range.crossplane: proves `observe` reconstructs a correlated session
  from telemetry produced by the actual emission paths the router/agent use.
"""
import os
import socket
import threading

import pytest

from src.agent.client import AgentClient
from src.agent.observatory import Event, Observer
from src.range.live import LiveSession
from src.utils import config


class _Capture:
    """Minimal EventSink that keeps emitted events for assertions."""

    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)

    def close(self):
        pass


def _fake_proxy(captured: dict):
    """A loopback server that speaks just enough CONNECT to satisfy the client:
    accept, 200, read the tunnelled request, return a canned response."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            conn, _ = srv.accept()
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
            captured["connect"] = head.decode(errors="ignore")
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            captured["request"] = req.decode(errors="ignore")
            body = b'{"ok":true}'
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close"
                         b"\r\n\r\n" + body)
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t


def test_live_session_threads_session_and_emits_research(monkeypatch):
    # Public mode: no experiment side effects; we just prove the bridge threads
    # the session id and emits correlated research events.
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    captured: dict = {}
    port, t = _fake_proxy(captured)
    cap = _Capture()
    sess = LiveSession("buyer-1", session_id="S-LIVE",
                       observer=Observer("buyer-1", sink=cap),
                       client=AgentClient(proxy_host="127.0.0.1",
                                          proxy_port=port))
    resp = sess.visit("shadow.bazaar", "/deals", port=80)
    t.join(timeout=3)

    assert resp.status == 200
    # The session id rode the CONNECT as X-Obscura-Session.
    assert "x-obscura-session: s-live" in captured["connect"].lower()
    # Research events were emitted under the same session id.
    kinds = {(e.kind, e.session_id) for e in cap.events}
    assert ("dial.out", "S-LIVE") in kinds
    assert ("dial.result", "S-LIVE") in kinds


def test_live_agent_reasons_and_acts_on_the_overlay(monkeypatch):
    # A model (replayed, deterministic) decides to visit a service then finish;
    # the decision executes for real through the session, emitting the agent's
    # reasoning AND its dial events under one session id.
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveAgent
    from src.range.llm_io import ReplayClient

    captured: dict = {}
    port, t = _fake_proxy(captured)
    cap = _Capture()
    sess = LiveSession("buyer-1", session_id="S-AGENT",
                       observer=Observer("buyer-1", sink=cap),
                       client=AgentClient(proxy_host="127.0.0.1",
                                          proxy_port=port))
    recs = [
        {"blocks": [{"input": {"kind": "visit", "addr": "shadow.bazaar",
                               "path": "/deals",
                               "rationale": "check the premium deals"},
                     "id": "t1"}],
         "usage": {"input_tokens": 50, "output_tokens": 10}},
        {"blocks": [{"input": {"kind": "finish", "rationale": "seen enough"},
                     "id": "t2"}],
         "usage": {"input_tokens": 40, "output_tokens": 5}},
    ]
    agent = LiveAgent("find premium deals", session=sess,
                      directory=[{"addr": "shadow.bazaar", "port": 80,
                                  "title": "Shadow Bazaar"}],
                      client=ReplayClient(recs))
    records = agent.run(max_steps=4)
    t.join(timeout=3)

    # The model visited, then finished - the loop stopped on finish.
    assert [r["kind"] for r in records] == ["visit", "finish"]
    assert "status 200" in records[0]["result_summary"]
    assert records[0]["rationale"] == "check the premium deals"
    assert agent.usage == {"calls": 2, "input_tokens": 90, "output_tokens": 15}
    # The real visit carried the session id on the wire.
    assert "x-obscura-session: s-agent" in captured["connect"].lower()
    # Research plane recorded both the reasoning and the dial, same session id.
    kinds = {(e.kind, e.session_id) for e in cap.events}
    assert ("agent.decision", "S-AGENT") in kinds
    assert ("dial.out", "S-AGENT") in kinds
    assert ("dial.result", "S-AGENT") in kinds


def _multi_fake_proxy():
    """Like _fake_proxy but serves multiple sequential CONNECT requests."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def run():
        while True:
            try:
                conn, _ = srv.accept()
            except Exception:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    def handle(conn):
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                c = conn.recv(4096)
                if not c:
                    return
                head += c
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            req = b""
            while b"\r\n\r\n" not in req:
                c = conn.recv(4096)
                if not c:
                    break
                req += c
            body = b'{"market":"Obscura Goods","listings":2}'
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                         + str(len(body)).encode()
                         + b"\r\nConnection: close\r\n\r\n" + body)
        except Exception:
            pass
        finally:
            conn.close()

    threading.Thread(target=run, daemon=True).start()
    return port, srv


def test_replay_of_recorded_real_claude_session(monkeypatch):
    # A real claude-sonnet-4-6 session on the live overlay, captured in
    # tests/fixtures/real_runs/live_agent_sonnet.json, replays deterministically
    # with no key. It is the permanent record of a real model acting on Obscura:
    # an exploratory agent that kept probing the service (/, /catalog, /tools).
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveAgent
    from src.range.llm_io import ReplayClient, load_recording

    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "real_runs",
                           "live_agent_sonnet.json")
    recs = load_recording(fixture)
    port, srv = _multi_fake_proxy()
    try:
        cap = _Capture()
        sess = LiveSession("buyer-1", session_id="S-REAL",
                           observer=Observer("buyer-1", sink=cap),
                           client=AgentClient(proxy_host="127.0.0.1",
                                              proxy_port=port))
        agent = LiveAgent("inspect the market", session=sess,
                          directory=[{"addr": "127.0.0.1", "port": 18381}],
                          client=ReplayClient(recs))
        records = agent.run(max_steps=len(recs))

        assert len(records) == len(recs)
        assert all(r["kind"] == "visit" for r in records)  # exploratory session
        # Its real reasoning is preserved verbatim.
        assert any("market" in (r["rationale"] or "").lower() for r in records)
        # Each visit produced a real dial under the session id.
        dials = [e for e in cap.events
                 if e.kind == "dial.out" and e.session_id == "S-REAL"]
        assert len(dials) == len(recs)
    finally:
        srv.close()


def test_live_defender_flags_and_bans_flagged_agents(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveDefender

    cap = _Capture()
    defender = LiveDefender("defender-1", observer=Observer("defender-1",
                                                            sink=cap),
                            session_id="SD")
    view = {"threats": {"flagged_agents": [
        {"agent": "attacker-1", "reasons": ["fanned out (recon)"]}]}}
    issued = defender.assess(view)

    assert issued == [{"defender": "defender-1", "target": "attacker-1",
                       "action": "ban", "reasons": ["fanned out (recon)"]}]
    # The response is two real research events: a flag and a ban.
    events = [(e.kind, e.payload.get("target"), e.payload.get("action"))
              for e in cap.events]
    assert ("defense.flag", "attacker-1", None) in events
    assert ("moderation.action", "attacker-1", "ban") in events


def _evt(actor, kind, **payload):
    return Event(event_id="e", ts=0.0, actor=actor, kind=kind, session_id="s",
                 payload=payload, submitted_by=None, experiment_id="x")


def test_live_escrow_releases_delivered_and_refunds_scam(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveEscrow

    cap = _Capture()
    escrow = LiveEscrow("escrow", observer=Observer("escrow", sink=cap),
                        session_id="SE", grace=1)
    events = [
        _evt("buyer-1", "escrow.open", seller="seller-1", item="widget",
             amount=50),
        _evt("buyer-1", "escrow.open", seller="seller-2", item="gadget",
             amount=30),
        _evt("seller-2", "delivery", buyer="buyer-1", item="gadget"),
    ]
    # First cycle: the delivered order is released; the undelivered one gets a
    # grace cycle.
    r1 = escrow.settle(events)
    assert any(x["settle"] == "release" and x["seller"] == "seller-2"
               for x in r1)
    assert not any(x["settle"] == "refund" for x in r1)
    # Second cycle: still no delivery from seller-1 -> refund + flag + ban.
    r2 = escrow.settle(events)
    assert any(x["settle"] == "refund" and x["seller"] == "seller-1"
               for x in r2)

    kinds = {(e.kind, e.payload.get("seller"), e.payload.get("target"),
              e.payload.get("action")) for e in cap.events}
    assert ("escrow.release", "seller-2", None, None) in kinds
    assert ("escrow.refund", "seller-1", None, None) in kinds
    assert ("moderation.action", None, "seller-1", "ban") in kinds


def _recon_view():
    return {"graph": {"agents": ["buyer-1", "attacker-1"], "edges": [
        {"src": "attacker-1", "dst": "a:1"}, {"src": "attacker-1", "dst": "a:2"},
        {"src": "attacker-1", "dst": "a:3"}, {"src": "buyer-1", "dst": "m"}]}}


def test_live_model_defender_bans_with_reasoning(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveModelDefender
    from src.range.llm_io import ReplayClient

    cap = _Capture()
    recs = [{"blocks": [{"input": {"kind": "ban", "target": "attacker-1",
                                   "rationale": "probed 3 services - recon"},
                         "id": "d1"}],
             "usage": {"input_tokens": 40, "output_tokens": 10}}]
    defn = LiveModelDefender("defender-1",
                             observer=Observer("defender-1", sink=cap),
                             session_id="SD", client=ReplayClient(recs))
    issued = defn.assess(_recon_view())

    assert issued and issued[0]["target"] == "attacker-1"
    assert issued[0]["action"] == "ban"
    kinds = {(e.kind, e.payload.get("target"), e.payload.get("action"))
             for e in cap.events}
    assert ("defense.decision", "attacker-1", None) in kinds
    assert ("defense.flag", "attacker-1", None) in kinds
    assert ("moderation.action", "attacker-1", "ban") in kinds
    # The model's reasoning rides the ban (shown on the dashboard).
    ban = next(e for e in cap.events if e.kind == "moderation.action")
    assert "recon" in ban.payload.get("reason", "")


def test_live_model_defender_allows_normal_agent(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    from src.range.live import LiveModelDefender
    from src.range.llm_io import ReplayClient

    cap = _Capture()
    recs = [{"blocks": [{"input": {"kind": "allow",
                                   "rationale": "agents look focused"},
                         "id": "d1"}], "usage": None}]
    defn = LiveModelDefender("defender-1",
                             observer=Observer("defender-1", sink=cap),
                             session_id="SD", client=ReplayClient(recs))
    issued = defn.assess({"graph": {"agents": ["buyer-1"],
                                    "edges": [{"src": "buyer-1", "dst": "m"}]}})
    assert issued == []
    kinds = {e.kind for e in cap.events}
    assert "defense.decision" in kinds and "moderation.action" not in kinds


class _StubObserver:
    def __init__(self):
        self.events = []

    def emit(self, kind, **payload):
        self.events.append((kind, payload))


class _StubSession:
    def __init__(self):
        self.session_id = "stub"
        self.observer = _StubObserver()


class _StubAgent:
    def __init__(self, kinds):
        self.kinds, self.i, self.steps = list(kinds), 0, 0
        self.session = _StubSession()

    def step(self, last=None):
        self.steps += 1
        k = self.kinds[self.i] if self.i < len(self.kinds) else "visit"
        self.i += 1
        return {"kind": k, "result_summary": f"r{self.steps}"}


class _StubDefender:
    def __init__(self, ban_round, target):
        self.actor, self.ban_round, self.target = "defender-1", ban_round, target
        self.round, self._done = 0, False

    def assess(self, view):
        self.round += 1
        if self.round >= self.ban_round and not self._done:
            self._done = True
            return [{"defender": self.actor, "target": self.target,
                     "action": "ban"}]
        return []


def test_run_society_interleaves_and_blocks_banned_agents():
    from src.range.live import run_society
    buyer = _StubAgent(["visit", "finish"])
    attacker = _StubAgent(["visit", "visit", "visit", "visit"])
    defender = _StubDefender(ban_round=3, target="attacker-1")

    transcript = run_society([("buyer-1", buyer), ("attacker-1", attacker)],
                             defender=defender, correlate=lambda: {}, rounds=5)

    # The attacker acts until banned after round 3, then is blocked.
    assert attacker.steps == 3
    bans = [t for t in transcript if t.get("banned") == "attacker-1"]
    assert len(bans) == 1 and bans[0]["round"] == 3
    blocked = [t for t in transcript
               if t.get("blocked") and t["actor"] == "attacker-1"]
    assert len(blocked) == 2  # rounds 4 and 5
    # Each blocked turn emitted an acted-while-banned policy violation.
    pv = [e for e in attacker.session.observer.events
          if e[0] == "policy.violation"]
    assert len(pv) == 2
    assert all(e[1].get("rule") == "acted_while_banned" for e in pv)


def test_live_agent_without_key_fails_clearly(monkeypatch):
    monkeypatch.setattr(config, "IS_RANGE_MODE", False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from src.range.live import LiveAgent
    sess = LiveSession("a", session_id="S", observer=Observer("a", sink=_Capture()),
                       client=AgentClient(proxy_host="127.0.0.1", proxy_port=1))
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        LiveAgent("goal", session=sess)


def test_real_trace_and_research_emission_correlate(monkeypatch, tmp_path):
    # Drive the REAL emission paths (trace.py spans + observatory events) under
    # range mode + diag into isolated temp dirs, then join with crossplane. This
    # proves `observe` works on genuinely-emitted telemetry, not hand-built JSON.
    from src.agent.observatory import JsonlSink
    from src.range import crossplane as cp
    from src.utils import diag, trace
    from src.utils import experiment as exp

    monkeypatch.setattr(config, "IS_RANGE_MODE", True)
    monkeypatch.setenv("OBSCURA_DIAG", "1")
    logs_dir = str(tmp_path / "logs")
    os.makedirs(logs_dir)
    monkeypatch.setattr(diag, "DIAG_DIR", logs_dir)
    monkeypatch.setattr(exp, "EXPERIMENTS_DIR", str(tmp_path / "exp"))
    monkeypatch.setattr(exp, "_current_id", None)
    monkeypatch.setattr(exp, "_env_resolved", False)

    eid, sid = "liveexp", "S-REAL"
    exp.set_experiment_id(eid)
    assert trace.is_active()  # range + diag => spans will emit

    # Research plane: the agent's dial, emitted to the experiment's durable log.
    obs = Observer("buyer-1", sink=JsonlSink(exp.events_path(eid)))
    obs.emit("dial.out", session_id=sid, addr="shadow.bazaar", method="GET",
             path="/")

    # Ops plane: emit a real 3-span circuit via the exact API the router calls.
    diag.set_role("proxy")
    block = trace.start_trace("req-1", session_id=sid, exit="9.9.9.9:80",
                              route_len=3)
    assert block is not None
    diag.set_role("node")
    block = trace.relay_span(block, request_id="req-1", frame_type="connect",
                             next_host="9.9.9.9", next_port=6000)
    diag.set_role("exit")
    trace.terminal_span(block, request_id="req-1", role="exit")

    obs.emit("dial.result", session_id=sid, addr="shadow.bazaar", status=200)

    view = cp.correlate(eid, logs_dir=logs_dir)
    assert view["coverage"]["fully_observable"] is True
    sess = next(s for s in view["sessions"] if s["session_id"] == sid)
    assert sess["observed_on_wire"] is True
    assert sess["made_research_dials"] is True
    assert len(sess["circuits"]) == 1
    assert sess["circuits"][0]["length"] == 3
    assert sess["circuits"][0]["exit"] == "9.9.9.9:80"
    # The merged timeline interleaves both planes: dial.out, the 3 spans, dial.result.
    planes = [it["plane"] for it in sess["timeline"]]
    assert planes == ["research", "ops", "ops", "ops", "research"]
