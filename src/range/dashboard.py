"""Render a run into a self-contained HTML dashboard.

The "fully observable" thesis, made visible. Given an ``experiment_id``, this
composes the reconstruction (:mod:`src.range.report`) and the scored evaluation
(:mod:`src.range.evaluate`) into a single static HTML file: verdict badge,
score bars, severity-ranked findings, the event timeline, the fake economy's
transactions, trust standings, and the adversarial investigation chain.

No web server, no JavaScript, no external dependencies - just a string of HTML
you can open in any browser or attach to an evaluation report. Works for any
persisted range run.

    OBSCURA_MODE=range python -m src.range.dashboard <experiment_id>
    OBSCURA_MODE=range python -m src.range.dashboard <experiment_id> -o run.html
"""

from __future__ import annotations

import argparse
import html
import os
import sys
from typing import Any

from src.range.evaluate import evaluate_run
from src.range.forensics import build_incidents
from src.range.report import build_report
from src.range.trajectory import build_trajectory
from src.utils import experiment

_VERDICT_COLOR = {
    "contained": "#2e7d32",
    "detected_not_fully_contained": "#ef6c00",
    "uncontained": "#c62828",
    "no_adversarial_activity": "#546e7a",
}
_SEV_COLOR = {
    "high": "#c62828", "medium": "#ef6c00", "low": "#f9a825",
    "info": "#546e7a", "positive": "#2e7d32",
}


def _esc(x: Any) -> str:
    return html.escape(str(x), quote=True)


def _bar(label: str, value: float, color: str) -> str:
    width = max(0.0, min(100.0, float(value)))
    return (
        f'<div class="bar"><span class="bl">{_esc(label)}</span>'
        f'<span class="bt">{value}</span>'
        f'<div class="btrack"><div class="bfill" '
        f'style="width:{width}%;background:{color}"></div></div></div>'
    )


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return '<p class="empty">none</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in r) + "</tr>"
        for r in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_html(experiment_id: str) -> str:
    report = build_report(experiment_id)
    ev = evaluate_run(experiment_id)
    rec = report.get("record") or {}
    s = ev["scores"]
    verdict = ev["verdict"]
    vcolor = _VERDICT_COLOR.get(verdict, "#546e7a")

    if report["event_count"] == 0 and report["record"] is None:
        body = (f'<p class="empty">No data for experiment '
                f'{_esc(experiment_id)}. Run a range scenario first.</p>')
        return _page(experiment_id, body)

    findings = "".join(
        f'<li><span class="sev" style="background:{_SEV_COLOR.get(f["severity"], "#546e7a")}">'
        f'{_esc(f["severity"].upper())}</span> <b>{_esc(f["title"])}</b>'
        f'<div class="fd">{_esc(f["detail"])}</div></li>'
        for f in ev["findings"]
    ) or '<li class="empty">none</li>'

    trust_rows = "".join(
        f'<div class="bar"><span class="bl">{_esc(subj)}</span>'
        f'<span class="bt">{score:+d}</span>'
        f'<div class="btrack"><div class="bfill" '
        f'style="width:{min(100, abs(score) * 12)}%;'
        f'background:{"#2e7d32" if score >= 0 else "#c62828"}"></div></div></div>'
        for subj, score in sorted(report["trust"].items())
    ) or '<p class="empty">no trust changes</p>'

    timeline = _table(
        ["actor", "event", "detail"],
        [[r["actor"], r["kind"], r["what"]] for r in report["timeline"]],
    )
    txns = _table(
        ["by", "kind", "amount"],
        [[t["by"], t["kind"], t["amount"]] for t in report["transactions"]],
    )

    investigations = ""
    for suspect, chain in report["investigations"].items():
        rows = _table(["actor", "event", "detail"],
                      [[c["actor"], c["kind"], c["what"]] for c in chain])
        investigations += (f'<h3>Investigation: {_esc(suspect)}</h3>{rows}')

    incidents = build_incidents(experiment_id)
    incidents_section = ""
    if incidents:
        rows = "".join(
            f'<tr><td><span class="sev" style="background:'
            f'{_SEV_COLOR.get(i["severity"], "#546e7a")}">'
            f'{_esc(i["severity"].upper())}</span></td>'
            f'<td>{_esc(i["suspect"])}</td>'
            f'<td>{_esc(", ".join(i["techniques"]) or "-")}</td>'
            f'<td>{_esc(i["funds_extracted"])}</td>'
            f'<td>{_esc(i["contained"])}</td></tr>'
            for i in incidents)
        incidents_section = (
            '<section><h2>Incidents</h2><table><thead><tr>'
            '<th>severity</th><th>suspect</th><th>techniques</th>'
            '<th>funds</th><th>contained</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></section>')

    traj = build_trajectory(experiment_id)
    trajectory_section = ""
    if traj:
        cols = ["round", "active_agents", "attacks", "defenses",
                "moderations", "volume", "trust_delta"]
        trajectory_section = (
            "<section><h2>Trajectory (per round)</h2>"
            + _table(cols, [[b.get(c, 0) for c in cols] for b in traj])
            + "</section>")

    decisions_section = ""
    if report.get("decisions"):
        rows = _table(
            ["round", "actor", "chose", "why"],
            [[d.get("round"), d.get("actor"), d.get("action"),
              d.get("rationale") or ""] for d in report["decisions"]])
        decisions_section = f'<section><h2>Decisions (why)</h2>{rows}</section>'

    cfg = ev.get("config") or {}
    body = f"""
    <div class="head">
      <h1>Experiment {_esc(experiment_id)}</h1>
      <span class="badge" style="background:{vcolor}">{_esc(verdict)}</span>
    </div>
    <p class="sub">scenario={_esc(rec.get('extra', {}).get('scenario'))} &middot;
       seed={_esc(rec.get('random_seed'))} &middot;
       commit={_esc((rec.get('code_commit_sha') or '')[:12])} &middot;
       model={_esc(cfg.get('model_id'))} &middot;
       events={_esc(report['event_count'])}</p>
    <p class="exec">{_esc(ev['executive_summary'])}</p>

    <div class="grid">
      <section><h2>Scores</h2>
        {_bar('threat level', s['threat_level'], '#8e24aa')}
        {_bar('defense efficacy', s['defense_efficacy'], '#2e7d32')}
        {_bar('residual risk', s['residual_risk'], '#c62828')}
      </section>
      <section><h2>Trust</h2>{trust_rows}</section>
    </div>

    <section><h2>Findings</h2><ul class="findings">{findings}</ul></section>
    <div class="grid">
      <section><h2>Transactions</h2>{txns}</section>
      <section><h2>Timeline</h2>{timeline}</section>
    </div>
    {incidents_section}
    {trajectory_section}
    <section><h2>Adversarial investigations</h2>{investigations or '<p class="empty">none</p>'}</section>
    {decisions_section}
    """
    return _page(experiment_id, body)


def _page(experiment_id: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Obscura47 range &middot; {_esc(experiment_id)}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;
   background:#0f1115;color:#e6e6e6;padding:24px}}
 h1{{font-size:20px;margin:0}} h2{{font-size:15px;border-bottom:1px solid #2a2e37;
   padding-bottom:6px;margin:0 0 10px}} h3{{font-size:14px;margin:16px 0 6px}}
 .head{{display:flex;align-items:center;gap:12px}}
 .badge,.sev{{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;
   font-weight:600;text-transform:uppercase;letter-spacing:.03em}}
 .sub{{color:#8b95a5;margin:6px 0 12px}} .exec{{background:#161922;
   border-left:3px solid #3a86ff;padding:10px 14px;border-radius:4px}}
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
 section{{background:#161922;border:1px solid #232734;border-radius:8px;
   padding:16px;margin:16px 0}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:5px 8px;border-bottom:1px solid #232734;
   vertical-align:top}} th{{color:#8b95a5;font-weight:600}}
 .bar{{display:flex;align-items:center;gap:8px;margin:6px 0}}
 .bl{{width:130px;color:#b8c0cc}} .bt{{width:48px;text-align:right;
   font-variant-numeric:tabular-nums}}
 .btrack{{flex:1;background:#232734;border-radius:4px;height:10px}}
 .bfill{{height:10px;border-radius:4px}}
 ul.findings{{list-style:none;padding:0;margin:0}}
 ul.findings li{{margin:8px 0}} .fd{{color:#8b95a5;margin:2px 0 0 4px}}
 .empty{{color:#5a6473;font-style:italic}}
</style></head><body>{body}</body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.range.dashboard",
        description="Render a run into a self-contained HTML dashboard.",
    )
    parser.add_argument("experiment_id")
    parser.add_argument("-o", "--out", default=None,
                        help="output path (default: alongside the run record)")
    args = parser.parse_args(argv)

    record = experiment.load_record(args.experiment_id)
    if record is None and not os.path.exists(
            experiment.events_path(args.experiment_id)):
        print(f"[dashboard] no record or events for {args.experiment_id!r}.",
              file=sys.stderr)
        return 1

    out = args.out or os.path.join(
        experiment.EXPERIMENTS_DIR, f"{args.experiment_id}.html")
    html_text = render_html(args.experiment_id)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html_text)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
