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
              logs_dir: str | None = None) -> dict[str, Any]:
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

    # Every session id seen in either plane.
    research_sessions = {getattr(e, "session_id", None) for e in events
                         if getattr(e, "session_id", None)}
    span_sessions = {c["session_id"] for c in circuits if c["session_id"]}
    all_sessions = sorted(research_sessions | span_sessions)

    sessions = []
    for sid in all_sessions:
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
    if cov["dial_sessions_unobserved"]:
        lines.append("WARNING: research dials with no ops trace (unobserved "
                     f"traffic): {cov['dial_sessions_unobserved']}")
    if cov["unattributed_circuits"]:
        lines.append(f"WARNING: {cov['unattributed_circuits']} ops circuit(s) "
                     "not attributable to any research session.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range observe",
        description="Join research events and ops trace spans into one "
                    "correlated cross-plane view of a run.")
    parser.add_argument("experiment_id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    view = correlate(args.experiment_id)
    rec = experiment.load_record(args.experiment_id)
    if rec is None and not view["sessions"] and not view["circuits"]:
        print(f"[observe] no record, events, or spans for "
              f"{args.experiment_id!r}.", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(view, indent=2, default=str))
    else:
        print(render_text(view))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
