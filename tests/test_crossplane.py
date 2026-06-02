"""Tests for the cross-plane observability join (src/range/crossplane.py).

Synthetic fixtures stand in for a real run: ops-plane trace spans written to a
temp diag logs dir (one file per role, as nodes really write them), and
research-plane Event objects. The join must reconstruct, per session, both what
the agent did and the network path its traffic took, and flag any gaps.
"""
import json
import os

from src.agent.observatory import Event
from src.range import crossplane as cp


def _ev(kind, session_id, ts, **payload):
    return Event(event_id=f"e{ts}", ts=ts, actor="buyer-1", kind=kind,
                 session_id=session_id, payload=payload, submitted_by=None,
                 experiment_id="exp1")


def _write_spans(logs_dir, role, records):
    with open(os.path.join(logs_dir, f"{role}.jsonl"), "w",
              encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _span(event, *, trace_id, span_id, parent, hop, role, session_id=None,
          ts=0.0, **extra):
    fields = {"trace_id": trace_id, "span_id": span_id,
              "parent_span_id": parent, "hop_index": hop, **extra}
    if session_id is not None:
        fields["session_id"] = session_id
    return {"ts": ts, "role": role, "node_id": role, "event": event,
            "experiment_id": "exp1", "fields": fields}


def _three_hop_logs(logs_dir, *, trace_id="T1", session_id="S1"):
    # origin (proxy) carries the session_id; relay + exit share the trace_id.
    _write_spans(logs_dir, "proxy", [
        _span("trace.start", trace_id=trace_id, span_id="sp0", parent=None,
              hop=0, role="proxy", session_id=session_id, ts=1.0,
              exit="9.9.9.9:80", route_len=3)])
    _write_spans(logs_dir, "node", [
        _span("hop.forward", trace_id=trace_id, span_id="sp1", parent="sp0",
              hop=1, role="node", ts=1.1, next_host="9.9.9.9", next_port=6000,
              frame_type="connect")])
    _write_spans(logs_dir, "exit", [
        _span("trace.terminal", trace_id=trace_id, span_id="sp2", parent="sp1",
              hop=2, role="exit", ts=1.2)])


def test_load_ops_spans_reads_all_role_files_and_filters(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d)
    # A span from another experiment must be filtered out.
    _write_spans(d, "other", [{"ts": 5, "role": "exit", "event": "trace.start",
                               "experiment_id": "other-exp",
                               "fields": {"trace_id": "X", "span_id": "z"}}])
    spans = cp.load_ops_spans("exp1", logs_dir=d)
    assert len(spans) == 3
    assert {s["event"] for s in spans} == {"trace.start", "hop.forward",
                                            "trace.terminal"}


def test_build_circuits_orders_hops_and_lifts_session(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d)
    circuits = cp.build_circuits(cp.load_ops_spans("exp1", logs_dir=d))
    assert len(circuits) == 1
    c = circuits[0]
    assert c["trace_id"] == "T1"
    assert c["session_id"] == "S1"          # lifted from the origin span
    assert c["length"] == 3
    assert [s["event"] for s in c["hops"]] == [
        "trace.start", "hop.forward", "trace.terminal"]
    assert c["exit"] == "9.9.9.9:80"


def test_correlate_joins_research_and_ops_by_session(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d, trace_id="T1", session_id="S1")
    events = [_ev("dial.out", "S1", 0.9, site="shadow.bazaar", method="GET"),
              _ev("dial.result", "S1", 1.5, status=200)]
    view = cp.correlate("exp1", events=events, logs_dir=d)
    assert len(view["sessions"]) == 1
    s = view["sessions"][0]
    assert s["session_id"] == "S1"
    assert s["observed_on_wire"] is True
    assert len(s["circuits"]) == 1
    # Timeline interleaves both planes in time order: dial.out, start, hop,
    # terminal, dial.result.
    kinds = [(it["plane"], it["kind"]) for it in s["timeline"]]
    assert kinds == [
        ("research", "dial.out"), ("ops", "trace.start"),
        ("ops", "hop.forward"), ("ops", "trace.terminal"),
        ("research", "dial.result")]
    assert view["coverage"]["fully_observable"] is True


def test_coverage_flags_research_dial_with_no_ops_trace(tmp_path):
    # The agent dialed (research plane) but no circuit was traced: traffic that
    # is NOT fully observable. This gap must be surfaced, not hidden.
    d = str(tmp_path)  # empty logs dir: no spans
    events = [_ev("dial.out", "S9", 1.0, site="x"),
              _ev("dial.result", "S9", 1.1, status=200)]
    view = cp.correlate("exp1", events=events, logs_dir=d)
    cov = view["coverage"]
    assert cov["dial_sessions_unobserved"] == ["S9"]
    assert cov["fully_observable"] is False
    assert view["sessions"][0]["observed_on_wire"] is False


def test_coverage_flags_unattributed_circuit(tmp_path):
    # A traced circuit whose session matches no research event: traffic on the
    # wire we cannot attribute to an agent decision.
    d = str(tmp_path)
    _three_hop_logs(d, trace_id="T1", session_id="S1")
    view = cp.correlate("exp1", events=[], logs_dir=d)
    assert view["coverage"]["unattributed_circuits"] == 1
    assert view["coverage"]["fully_observable"] is False


def test_render_text_tells_the_two_plane_story(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d)
    events = [_ev("dial.out", "S1", 0.9, site="shadow.bazaar")]
    out = cp.render_text(cp.correlate("exp1", events=events, logs_dir=d))
    assert "Cross-plane observation" in out
    assert "session S1" in out
    assert "circuit T1" in out
    assert "[R]" in out and "[O]" in out          # both planes on the timeline


def test_render_html_visualizes_the_session_and_circuit(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d)
    events = [_ev("dial.out", "S1", 0.9, site="shadow.bazaar", method="GET"),
              _ev("dial.result", "S1", 1.5, status=200)]
    html = cp.render_html(cp.correlate("exp1", events=events, logs_dir=d))
    assert "<!DOCTYPE html>" in html and "</html>" in html
    assert "What the agents did on Obscura" in html
    assert "session S1" in html
    assert "circuit T1" in html
    # The hop chain through the overlay is visualized (origin -> relay -> exit).
    assert "origin" in html and "relay" in html and "exit" in html
    assert "fully observable" in html
    # Both planes are tagged on the timeline.
    assert "RESEARCH" in html and "OPS" in html


def test_render_html_surfaces_unattributed_traffic(tmp_path):
    # A circuit with no matching agent decision must be shown as unattributed.
    d = str(tmp_path)
    _three_hop_logs(d, trace_id="T1", session_id="S1")
    html = cp.render_html(cp.correlate("exp1", events=[], logs_dir=d))
    assert "Unattributed traffic" in html


def _ev_actor(actor, kind, session_id, ts, **payload):
    return Event(event_id=f"e{actor}{ts}", ts=ts, actor=actor, kind=kind,
                 session_id=session_id, payload=payload, submitted_by=None,
                 experiment_id="exp1")


def test_traffic_graph_maps_who_dialed_whom_across_agents(tmp_path):
    # Two agents dial the same service; only the buyer's traffic was traced.
    d = str(tmp_path)
    _three_hop_logs(d, trace_id="T1", session_id="S1")  # buyer's circuit only
    events = [
        _ev_actor("buyer-1", "dial.out", "S1", 1.0, addr="shadow.bazaar"),
        _ev_actor("attacker-1", "dial.out", "S2", 2.0, addr="shadow.bazaar"),
    ]
    view = cp.correlate("exp1", events=events, logs_dir=d,
                        hosts={"shadow.bazaar": "seller-1"})
    g = view["graph"]
    assert set(g["agents"]) == {"buyer-1", "attacker-1"}
    assert "shadow.bazaar" in g["services"]
    edges = {(e["src"], e["dst"]): e for e in g["edges"]}
    # The buyer's dial was observed on the wire; the attacker's was not.
    assert edges[("buyer-1", "shadow.bazaar")]["observed"] is True
    assert edges[("attacker-1", "shadow.bazaar")]["observed"] is False
    # The service collapses to its hosting agent (the social edge).
    assert edges[("buyer-1", "shadow.bazaar")]["dst_agent"] == "seller-1"


def test_graph_renders_in_text_and_html(tmp_path):
    d = str(tmp_path)
    _three_hop_logs(d, trace_id="T1", session_id="S1")
    events = [_ev_actor("buyer-1", "dial.out", "S1", 1.0, addr="shadow.bazaar"),
              _ev_actor("attacker-1", "dial.out", "S2", 2.0, addr="market.x")]
    view = cp.correlate("exp1", events=events, logs_dir=d)
    text = cp.render_text(view)
    assert "traffic graph (who dialed whom)" in text
    assert "buyer-1 -> shadow.bazaar" in text
    html = cp.render_html(view)
    assert "Traffic graph" in html and "who dialed whom" in html
    assert "attacker-1" in html and "market.x" in html
