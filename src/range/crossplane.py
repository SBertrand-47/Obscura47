"""Join the two telemetry planes into one observable story per agent session.

This is the keystone of the observability thesis - "a dark web for agents, but
fully observable". Two planes capture a run from different angles:

* the **research plane** (:mod:`src.agent.observatory`) - *what did the agent
  do?* Its events carry a ``session_id``.
* the **ops plane** (:mod:`src.utils.trace` via :mod:`src.utils.diag`) - *how
  did its traffic actually flow through the overlay?* Each circuit is a tree of
  spans sharing a ``trace_id``; the origin span (``trace.start``) carries the
  ``session_id`` that the agent client put in its ``X-Obscura-Session`` header.

Separately, each plane only answers half the question. Joined on ``session_id``
they answer the whole one: for a given agent session you see the decision it
made *and* the path its bytes took, on one timeline. This module is that join.
It is a pure reader over the durable logs, so it works on any persisted run and
needs no live network.

    OBSCURA_MODE=range python -m src.range observe <experiment_id>
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any

from src.range.report import load_events
from src.utils import experiment

# The ops-plane span kinds (see src/utils/trace.py).
_TRACE_START = "trace.start"
_HOP_FORWARD = "hop.forward"
_TRACE_TERMINAL = "trace.terminal"
_SPAN_KINDS = (_TRACE_START, _HOP_FORWARD, _TRACE_TERMINAL)

# Research-plane event kinds that represent a network dial (see client.py).
_DIAL_KINDS = ("dial.out", "dial.result", "dial.error")


def _diag_dir() -> str:
    from src.utils.diag import DIAG_DIR
    return DIAG_DIR


def load_ops_spans(experiment_id: str | None = None, *,
                   logs_dir: str | None = None) -> list[dict[str, Any]]:
    """Read ops-plane trace spans from the diag JSONL logs.

    Flattens each span's ``fields`` up to the top level and keeps only trace
    spans. Filters to ``experiment_id`` when given. Reads every ``{role}.jsonl``
    (and rolled ``.1``) in the logs directory, since each node writes its own.
    """
    logs_dir = logs_dir if logs_dir is not None else _diag_dir()
    spans: list[dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(logs_dir, "*.jsonl"))) + \
            sorted(glob.glob(os.path.join(logs_dir, "*.jsonl.1"))):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("event") not in _SPAN_KINDS:
                        continue
                    if (experiment_id is not None
                            and rec.get("experiment_id") != experiment_id):
                        continue
                    fields = rec.get("fields") or {}
                    spans.append({
                        "ts": rec.get("ts"),
                        "role": rec.get("role"),
                        "node_id": rec.get("node_id"),
                        "event": rec.get("event"),
                        "experiment_id": rec.get("experiment_id"),
                        "trace_id": fields.get("trace_id"),
                        "span_id": fields.get("span_id"),
                        "parent_span_id": fields.get("parent_span_id"),
                        "hop_index": fields.get("hop_index"),
                        "session_id": fields.get("session_id"),
                        "fields": fields,
                    })
        except OSError:
            continue
    return spans


def build_circuits(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group spans by ``trace_id`` into ordered circuits (origin -> exit).

    The ``session_id`` rides only on the origin (``trace.start``) span, so it is
    lifted onto the whole circuit. Spans are ordered by hop index then time.
    """
    by_trace: dict[str, list[dict]] = {}
    for s in spans:
        if s.get("trace_id") is None:
            continue
        by_trace.setdefault(s["trace_id"], []).append(s)

    circuits = []
    for trace_id, group in by_trace.items():
        group.sort(key=lambda s: (s.get("hop_index") or 0, s.get("ts") or 0))
        session_id = next((s.get("session_id") for s in group
                           if s.get("event") == _TRACE_START
                           and s.get("session_id")), None)
        terminal = next((s for s in group
                         if s.get("event") == _TRACE_TERMINAL), None)
        origin = next((s for s in group
                       if s.get("event") == _TRACE_START), None)
        exit_target = (origin or {}).get("fields", {}).get("exit")
        circuits.append({
            "trace_id": trace_id,
            "session_id": session_id,
            "hops": group,
            "length": len(group),
            "exit": exit_target,
            "terminal_role": (terminal or {}).get("role"),
            "started_at": min((s.get("ts") or 0) for s in group),
        })
    circuits.sort(key=lambda c: c["started_at"])
    return circuits


def correlate(experiment_id: str | None = None, *,
              events: list[Any] | None = None,
              spans: list[dict[str, Any]] | None = None,
              logs_dir: str | None = None,
              hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """Join research events and ops spans by ``session_id`` for one run.

    Returns a per-session view (the agent's research events plus the network
    circuits its traffic took), a merged cross-plane timeline, and a coverage
    summary that flags the gaps - the parts of the run that are *not* fully
    observable. ``events`` / ``spans`` may be injected (for tests); otherwise
    they are loaded from durable storage for ``experiment_id``.
    """
    if events is None:
        events = load_events(experiment_id) if experiment_id else []
    if spans is None:
        spans = load_ops_spans(experiment_id, logs_dir=logs_dir)

    circuits = build_circuits(spans)
    circuits_by_session: dict[str | None, list[dict]] = {}
    for c in circuits:
        circuits_by_session.setdefault(c["session_id"], []).append(c)

    # Sessions are agent-decision-centric: built from research events (what the
    # agent did). Circuits that match no research session are "unattributed"
    # traffic - seen on the wire but not tied to any decision.
    research_sessions = {getattr(e, "session_id", None) for e in events
                         if getattr(e, "session_id", None)}
    span_sessions = {c["session_id"] for c in circuits if c["session_id"]}

    sessions = []
    for sid in sorted(research_sessions):
        s_events = [e for e in events if getattr(e, "session_id", None) == sid]
        s_circuits = circuits_by_session.get(sid, [])
        sessions.append({
            "session_id": sid,
            "research_events": s_events,
            "circuits": s_circuits,
            "observed_on_wire": bool(s_circuits),
            "made_research_dials": any(getattr(e, "kind", None) in _DIAL_KINDS
                                       for e in s_events),
            "timeline": _merge_timeline(s_events, s_circuits),
        })

    # Coverage: where observability is complete vs broken.
    dial_sessions = {getattr(e, "session_id", None) for e in events
                     if getattr(e, "kind", None) in _DIAL_KINDS
                     and getattr(e, "session_id", None)}
    unobserved = sorted(s for s in dial_sessions if s not in span_sessions)
    unattributed = [c for c in circuits
                    if not c["session_id"] or c["session_id"]
                    not in research_sessions]
    coverage = {
        "research_sessions": len(research_sessions),
        "ops_circuits": len(circuits),
        "sessions_observed_on_wire": len(
            [s for s in sessions if s["observed_on_wire"]]),
        "dial_sessions": len(dial_sessions),
        "dial_sessions_unobserved": unobserved,
        "unattributed_circuits": len(unattributed),
        "fully_observable": (not unobserved and not unattributed
                             and bool(circuits)),
    }
    return {
        "experiment_id": experiment_id,
        "sessions": sessions,
        "circuits": circuits,
        "coverage": coverage,
        "graph": traffic_graph(sessions, hosts=hosts),
    }


def _session_actor(session: dict[str, Any]) -> str | None:
    """The agent behind a session: the actor that emitted its research events."""
    for e in session["research_events"]:
        actor = getattr(e, "actor", None)
        if actor:
            return actor
    return None


def traffic_graph(sessions: list[dict[str, Any]],
                  hosts: dict[str, str] | None = None) -> dict[str, Any]:
    """The cross-agent traffic graph: who dialed whom, across all sessions.

    Nodes are agents and the services they reached; an edge is an agent dialing
    a service, with a dial count and whether that traffic was observed on the
    wire. ``hosts`` optionally maps a service address to the agent hosting it, so
    a dial collapses into an agent-to-agent edge - the social graph of the run.
    """
    hosts = hosts or {}
    agents: set[str] = set()
    services: set[str] = set()
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for s in sessions:
        actor = _session_actor(s) or s["session_id"]
        agents.add(actor)
        observed = s["observed_on_wire"]
        for e in s["research_events"]:
            if getattr(e, "kind", None) != "dial.out":
                continue
            dst = (getattr(e, "payload", {}) or {}).get("addr")
            if not dst:
                continue
            services.add(dst)
            ent = edges.setdefault((actor, dst), {
                "src": actor, "dst": dst, "dst_agent": hosts.get(dst),
                "dials": 0, "observed": False})
            ent["dials"] += 1
            ent["observed"] = ent["observed"] or observed
    return {
        "agents": sorted(agents),
        "services": sorted(services),
        "edges": [edges[k] for k in sorted(edges)],
        "hosts": dict(hosts),
    }


def _merge_timeline(events: list[Any],
                    circuits: list[dict]) -> list[dict[str, Any]]:
    """Interleave one session's research events and ops spans by timestamp."""
    items: list[dict[str, Any]] = []
    for e in events:
        items.append({
            "ts": getattr(e, "ts", 0) or 0,
            "plane": "research",
            "kind": getattr(e, "kind", "?"),
            "actor": getattr(e, "actor", None),
            "detail": _event_detail(e),
        })
    for c in circuits:
        for span in c["hops"]:
            items.append({
                "ts": span.get("ts") or 0,
                "plane": "ops",
                "kind": span.get("event"),
                "actor": span.get("role"),
                "detail": _span_detail(span),
            })
    items.sort(key=lambda i: i["ts"])
    return items


def _event_detail(e: Any) -> str:
    payload = getattr(e, "payload", {}) or {}
    bits = [f"{k}={payload[k]}" for k in ("method", "path", "status", "site",
                                          "addr") if k in payload]
    return " ".join(bits)


def _span_detail(span: dict) -> str:
    f = span.get("fields", {})
    if span["event"] == _HOP_FORWARD:
        return f"-> {f.get('next_host')}:{f.get('next_port')} ({f.get('frame_type')})"
    if span["event"] == _TRACE_START:
        return f"exit={f.get('exit')} route_len={f.get('route_len')}"
    return f"terminal@{span.get('role')}"


# ── Rendering ─────────────────────────────────────────────────────

def render_text(view: dict[str, Any]) -> str:
    cov = view["coverage"]
    lines = [
        f"Cross-plane observation  experiment={view.get('experiment_id') or '-'}",
        f"  research sessions: {cov['research_sessions']}  "
        f"ops circuits: {cov['ops_circuits']}  "
        f"observed on wire: {cov['sessions_observed_on_wire']}",
        f"  fully observable: {cov['fully_observable']}",
        "",
    ]
    if not view["sessions"]:
        lines.append("  (no correlated sessions)")
    for s in view["sessions"]:
        flag = "observed" if s["observed_on_wire"] else "NOT on wire"
        lines.append(f"session {s['session_id']}  [{flag}]")
        for c in s["circuits"]:
            lines.append(f"  circuit {c['trace_id']}  hops={c['length']}  "
                         f"exit={c['exit']}")
        lines.append("  timeline:")
        for it in s["timeline"]:
            tag = "R" if it["plane"] == "research" else "O"
            lines.append(f"    [{tag}] {it['kind']:<16} {it['actor'] or '':<10} "
                         f"{it['detail']}")
        lines.append("")
    graph = view.get("graph") or {}
    if graph.get("edges"):
        lines.append("traffic graph (who dialed whom):")
        for e in graph["edges"]:
            dst = e["dst"]
            if e.get("dst_agent"):
                dst = f"{dst} [{e['dst_agent']}]"
            flag = "observed" if e["observed"] else "unobserved"
            lines.append(f"  {e['src']} -> {dst}  "
                         f"({e['dials']} dial(s), {flag})")
        lines.append("")
    if cov["dial_sessions_unobserved"]:
        lines.append("WARNING: research dials with no ops trace (unobserved "
                     f"traffic): {cov['dial_sessions_unobserved']}")
    if cov["unattributed_circuits"]:
        lines.append(f"WARNING: {cov['unattributed_circuits']} ops circuit(s) "
                     "not attributable to any research session.")
    return "\n".join(lines)


def _esc(x: Any) -> str:
    import html
    return html.escape(str(x), quote=True)


def _circuit_path_html(circuit: dict) -> str:
    """Render a circuit as a visual hop chain: origin -> relays -> exit."""
    nodes = []
    for span in circuit["hops"]:
        f = span.get("fields", {})
        if span["event"] == _TRACE_START:
            label, sub = "origin", span.get("role") or "proxy"
        elif span["event"] == _HOP_FORWARD:
            label = "relay"
            sub = f"{span.get('role') or 'node'} -> {f.get('next_host')}:{f.get('next_port')}"
        else:
            label, sub = "exit", span.get("role") or "exit"
        nodes.append(
            f'<span class="hop"><b>{_esc(label)}</b>'
            f'<small>{_esc(sub)}</small></span>')
    chain = '<span class="arrow">&rarr;</span>'.join(nodes)
    exit_t = circuit.get("exit")
    tail = f' <span class="hop dest"><b>service</b><small>{_esc(exit_t)}</small></span>' \
        if exit_t else ""
    return f'<div class="circuit">{chain}{tail}</div>'


def _timeline_html(timeline: list[dict]) -> str:
    rows = ""
    for it in timeline:
        cls = "r" if it["plane"] == "research" else "o"
        tag = "RESEARCH" if it["plane"] == "research" else "OPS"
        rows += (f'<tr class="{cls}"><td class="pl">{tag}</td>'
                 f'<td>{_esc(it["kind"])}</td>'
                 f'<td>{_esc(it["actor"] or "")}</td>'
                 f'<td>{_esc(it["detail"])}</td></tr>')
    return (f'<table class="tl"><thead><tr><th>plane</th><th>event</th>'
            f'<th>actor</th><th>detail</th></tr></thead><tbody>{rows}'
            f'</tbody></table>')


def render_html(view: dict[str, Any]) -> str:
    """Render the correlated cross-plane view as a self-contained HTML page."""
    cov = view["coverage"]
    obs_color = "#2e7d32" if cov["fully_observable"] else "#ef6c00"
    sessions_html = ""
    for s in view["sessions"]:
        on_wire = s["observed_on_wire"]
        badge = ("#2e7d32", "observed on wire") if on_wire else \
            ("#c62828", "NOT traced on wire")
        circuits = "".join(
            f'<div class="cwrap"><div class="ctitle">circuit '
            f'{_esc(c["trace_id"])} &middot; {c["length"]} hops</div>'
            f'{_circuit_path_html(c)}</div>' for c in s["circuits"]) \
            or '<p class="empty">no ops trace for this session</p>'
        sessions_html += (
            f'<section><div class="shead"><h2>session {_esc(s["session_id"])}</h2>'
            f'<span class="badge" style="background:{badge[0]}">{badge[1]}</span>'
            f'</div>{circuits}<h3>timeline (both planes)</h3>'
            f'{_timeline_html(s["timeline"])}</section>')

    # Traffic on the wire we cannot attribute to any agent session.
    unattributed = [c for c in view["circuits"]
                    if not c["session_id"]
                    or c["session_id"] not in {s["session_id"]
                                               for s in view["sessions"]}]
    unattr_html = ""
    if unattributed:
        items = "".join(f'<div class="cwrap"><div class="ctitle">circuit '
                        f'{_esc(c["trace_id"])} (session={_esc(c["session_id"])})'
                        f'</div>{_circuit_path_html(c)}</div>'
                        for c in unattributed)
        unattr_html = (f'<section><h2>Unattributed traffic</h2>'
                       f'<p class="sub">Circuits seen on the wire with no '
                       f'matching agent decision.</p>{items}</section>')

    # Cross-agent traffic graph: who dialed whom across the whole run.
    graph = view.get("graph") or {}
    graph_html = ""
    if graph.get("edges"):
        grows = ""
        for e in graph["edges"]:
            dst = _esc(e["dst"])
            if e.get("dst_agent"):
                dst += f' <small>[{_esc(e["dst_agent"])}]</small>'
            ocol = "#2e7d32" if e["observed"] else "#c62828"
            otext = "observed" if e["observed"] else "unobserved"
            grows += (f'<tr><td><b>{_esc(e["src"])}</b></td>'
                      f'<td class="arrow">&rarr;</td><td>{dst}</td>'
                      f'<td>{_esc(e["dials"])}</td>'
                      f'<td><span class="badge" style="background:{ocol}">'
                      f'{otext}</span></td></tr>')
        graph_html = (
            f'<section><h2>Traffic graph &middot; who dialed whom</h2>'
            f'<p class="sub">{len(graph["agents"])} agent(s), '
            f'{len(graph["services"])} service(s)</p>'
            f'<table class="tl"><thead><tr><th>agent</th><th></th>'
            f'<th>service</th><th>dials</th><th>wire</th></tr></thead>'
            f'<tbody>{grows}</tbody></table></section>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Obscura observe &middot; {_esc(view.get('experiment_id') or '')}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;
   background:#0f1115;color:#e6e6e6;padding:28px;max-width:1000px}}
 h1{{font-size:22px;margin:0}} h2{{font-size:15px;margin:0}}
 h3{{font-size:13px;color:#8b95a5;margin:14px 0 4px}}
 .sub{{color:#8b95a5;margin:4px 0 14px}}
 .badge{{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;
   font-weight:600;text-transform:uppercase;letter-spacing:.03em}}
 section{{background:#161922;border:1px solid #232734;border-radius:8px;
   padding:16px;margin:14px 0}}
 .shead{{display:flex;align-items:center;justify-content:space-between;gap:12px}}
 .circuit{{display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin:8px 0}}
 .hop{{display:inline-flex;flex-direction:column;background:#1d2230;
   border:1px solid #2c3344;border-radius:6px;padding:6px 10px;min-width:60px}}
 .hop b{{font-size:12px;text-transform:uppercase;letter-spacing:.03em;
   color:#7aa2f7}} .hop small{{color:#8b95a5;font-size:11px}}
 .hop.dest b{{color:#9ece6a}} .arrow{{color:#5a6473;padding:0 2px}}
 .ctitle{{color:#8b95a5;font-size:12px;margin-top:8px}}
 table.tl{{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}}
 .tl th,.tl td{{text-align:left;padding:4px 8px;border-bottom:1px solid #232734}}
 .tl th{{color:#8b95a5}} .tl td.pl{{font-weight:600;width:80px}}
 .tl tr.r td.pl{{color:#7aa2f7}} .tl tr.o td.pl{{color:#9ece6a}}
 .empty{{color:#5a6473;font-style:italic}}
</style></head><body>
<h1>What the agents did on Obscura</h1>
<p class="sub">experiment {_esc(view.get('experiment_id') or '-')} &middot;
 <span class="badge" style="background:{obs_color}">
 {'fully observable' if cov['fully_observable'] else 'observability gaps'}</span>
 &middot; {cov['research_sessions']} research sessions &middot;
 {cov['ops_circuits']} ops circuits &middot;
 {cov['sessions_observed_on_wire']} observed on wire</p>
{graph_html}
{sessions_html or '<p class="empty">no correlated sessions</p>'}
{unattr_html}
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range observe",
        description="Join research events and ops trace spans into one "
                    "correlated cross-plane view of a run.")
    parser.add_argument("experiment_id")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--html", default=None,
                        help="write a visual HTML view to this path")
    args = parser.parse_args(argv)

    view = correlate(args.experiment_id)
    rec = experiment.load_record(args.experiment_id)
    if rec is None and not view["sessions"] and not view["circuits"]:
        print(f"[observe] no record, events, or spans for "
              f"{args.experiment_id!r}.", file=sys.stderr)
        return 1
    if args.html:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(view))
        print(args.html)
    if args.json:
        print(json.dumps(view, indent=2, default=str))
    elif not args.html:
        print(render_text(view))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
