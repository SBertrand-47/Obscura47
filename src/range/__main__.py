"""Unified entry point for the Obscura47 agent research range.

One tool over the whole stack. ``run`` is the turnkey path: execute a scenario,
score it into an evidence package, and (in range mode) emit a dashboard, all in
one command. The other subcommands dispatch to the focused tools.

    python -m src.range run --kind readiness
    python -m src.range run --kind adaptive --defender weak --rounds 10
    OBSCURA_MODE=range python -m src.range run --kind agents --dashboard
    python -m src.range report   <experiment_id>
    python -m src.range evaluate <experiment_id>
    python -m src.range dashboard <experiment_id> -o run.html
    python -m src.range compare
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from src.range import adaptive as _adaptive
from src.range import agents as _agents
from src.range import compare as _compare
from src.range import dashboard as _dashboard
from src.range import evaluate as _evaluate
from src.range import evidence as _evidence
from src.range import gate as _gate
from src.range import matrix as _matrix
from src.range import report as _report
from src.range import scenario as _scenario
from src.range import suite as _suite
from src.range.evaluate import build_evaluation
from src.utils import experiment


def _score(result) -> dict[str, Any]:
    events = list(reversed(result.collector.query(limit=10_000)))
    rec = experiment.load_record(result.experiment_id)
    ev = build_evaluation(events, rec.to_dict() if rec else None)
    ev["experiment_id"] = result.experiment_id
    ev["event_count"] = len(events)
    return ev


def _llm_client(record_path, replay_path):
    """Shared model client for LLM agents: a ReplayClient (key-free, from a
    recording), a RecordingClient (wraps a real client, captures the run), or
    None (each LLMPolicy builds its own real client)."""
    if replay_path:
        from src.range.llm_io import ReplayClient, load_recording
        return ReplayClient(load_recording(replay_path))
    if record_path:
        from src.range.llm_io import RecordingClient
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("recording requires the 'anthropic' package "
                               "(pip install anthropic).") from e
        import os
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "recording requires ANTHROPIC_API_KEY in the environment.")
        return RecordingClient(anthropic.Anthropic())
    return None


def run_pipeline(
    *, kind: str = "readiness", rounds: int = 8, seed: int = 47,
    defender: str = "weak", llm_roles: set[str] | None = None,
    make_dashboard: bool = False, record_path: str | None = None,
    replay_path: str | None = None,
) -> dict[str, Any]:
    """Run a scenario end to end and return the evidence package.

    Includes a dashboard path when the run was persisted (range mode) and
    ``make_dashboard`` is set. ``record_path`` captures an LLM run for replay;
    ``replay_path`` re-runs a recording deterministically without a key. Both
    apply to the ``agents`` kind with ``llm_roles``.
    """
    if kind == "readiness":
        result = _scenario.run_scenario(seed=seed)
    elif kind == "adaptive":
        result = _adaptive.run_adaptive(
            rounds=rounds, seed=seed,
            defender=_adaptive.DEFENDERS[defender])
    elif kind == "agents":
        shared = _llm_client(record_path, replay_path)
        factory = None
        if llm_roles:
            factory = lambda role, goal: (  # noqa: E731
                _agents.LLMPolicy(role, goal, client=shared)
                if role in llm_roles else _agents.ScriptedPolicy())
        result = _agents.run_world(
            _agents.default_cast(factory), rounds=rounds, seed=seed)
        if record_path and shared is not None:
            from src.range.llm_io import save_recording
            save_recording(shared, record_path)
    else:
        raise ValueError(f"unknown scenario kind: {kind!r}")

    ev = _score(result)
    dash_path = None
    if make_dashboard and experiment.load_record(result.experiment_id):
        dash_path = os.path.join(
            experiment.EXPERIMENTS_DIR, f"{result.experiment_id}.html")
        os.makedirs(os.path.dirname(os.path.abspath(dash_path)), exist_ok=True)
        with open(dash_path, "w", encoding="utf-8") as f:
            f.write(_dashboard.render_html(result.experiment_id))

    return {"experiment_id": result.experiment_id, "evaluation": ev,
            "dashboard": dash_path}


def _run_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range run",
        description="Run a scenario, score it, and optionally emit a dashboard.")
    parser.add_argument("--kind", choices=("readiness", "adaptive", "agents"),
                        default="readiness")
    parser.add_argument("--rounds", type=int, default=8)
    parser.add_argument("--seed", type=int, default=47)
    parser.add_argument("--defender", choices=sorted(_adaptive.DEFENDERS),
                        default="weak", help="adaptive: defender model")
    parser.add_argument("--llm-roles", default="",
                        help="agents: comma-separated roles driven by a model")
    parser.add_argument("--dashboard", action="store_true",
                        help="write an HTML dashboard (range mode only)")
    parser.add_argument("--record", default=None,
                        help="agents: capture the LLM run to this path")
    parser.add_argument("--replay", default=None,
                        help="agents: replay a recording (deterministic, no key)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    raw = (args.llm_roles or "").strip().lower()
    llm_roles = set() if raw in ("", "none") else {
        r.strip() for r in raw.split(",") if r.strip()}

    try:
        out = run_pipeline(kind=args.kind, rounds=args.rounds, seed=args.seed,
                           defender=args.defender, llm_roles=llm_roles,
                           make_dashboard=args.dashboard,
                           record_path=args.record, replay_path=args.replay)
    except (RuntimeError, FileNotFoundError) as e:  # no key, or bad recording
        print(f"[range] {e}", file=sys.stderr)
        return 1

    ev = out["evaluation"]
    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    eid = out["experiment_id"]
    s = ev["scores"]
    print(f"Range run  kind={args.kind}  experiment={eid}")
    print(f"  verdict={ev['verdict']}  threat={s['threat_level']}  "
          f"efficacy={s['defense_efficacy']}  residual={s['residual_risk']}")
    print(f"  {ev['executive_summary']}")
    if experiment.load_record(eid):
        print(f"  record:  {experiment._record_path(eid)}")
        print(f"  events:  {experiment.events_path(eid)}")
        print(f"  report:  python -m src.range.report {eid}")
    else:
        print("  (set OBSCURA_MODE=range to persist a replayable run)")
    if out["dashboard"]:
        print(f"  dashboard: {out['dashboard']}")
    return 0


_DISPATCH = {
    "report": _report.main,
    "evaluate": _evaluate.main,
    "compare": _compare.main,
    "dashboard": _dashboard.main,
    "adaptive": _adaptive.main,
    "agents": _agents.main,
    "scenario": _scenario.main,
    "matrix": _matrix.main,
    "gate": _gate.main,
    "suite": _suite.main,
    "evidence": _evidence.main,
}

_USAGE = ("usage: python -m src.range {run|report|evaluate|compare|dashboard|"
          "adaptive|agents|scenario|matrix|gate|suite|evidence} [args...]")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(_USAGE)
        return 0 if argv[:1] in ([], ["-h"], ["--help"]) else 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "run":
        return _run_main(rest)
    if cmd in _DISPATCH:
        return _DISPATCH[cmd](rest)
    print(f"[range] unknown subcommand {cmd!r}\n{_USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
