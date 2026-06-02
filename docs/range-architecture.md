# Agent Research Range: Architecture and Extension Guide

How `src/range/` is put together and how to extend it. For the why (the
observability design, the two telemetry planes), see
[`observability.md`](observability.md); for usage, see
[`src/range/README.md`](../src/range/README.md).

## One event stream

Everything flows through a single research-event stream. A run produces
`Event`s (`src/agent/observatory.py`), each stamped with the run's
`experiment_id`; in range mode they are also appended to a durable log
(`~/.obscura47/experiments/<id>.events.jsonl`). Every analysis tool is a pure
reader over that stream, so scripted, adaptive, and real-model runs are analysed
identically.

Event kinds (`src/range/scenario.py`): `agent.online`, `site.host`,
`site.visit`, `market.list`, `bank.mint`, `bank.transfer`, `escrow.open`,
`escrow.release`, `trust.update`, `attack.attempt`, `policy.violation`,
`defense.flag`, `moderation.action`, `tool.misuse`, `agent.decision`,
`forum.post`, `node.unstable`.

## The run model

`run_world(agents, rounds, ...)` is the engine. Each round, every agent is given
a partial `Observation` (its balance, visible listings, public events so far,
trust, forum) and returns an `Action` through its `Policy`; `_apply` applies the
action and emits events. The world also runs escrow settlement at each round
start and (opt-in) records a per-agent decision trace.

* `Policy` is the seam: `decide(observation) -> Action`.
  * `ScriptedPolicy` and the per-role attacker/defender policies are
    deterministic.
  * `LLMPolicy` asks a Claude model (tool-forced structured output, prompt
    cache, conversation memory, token accounting). It is a drop-in: the engine
    is unchanged. Optional (`anthropic` + key); never affects the deterministic
    path.
* `scenario.py` (scripted storyline) and `adaptive.py` (multi-round learning
  attacker vs defender) are alternative run shapes over the same event schema.

## Threat families and their controls

Each adversarial behaviour is paired with a control; the behavioral suite runs
both sides so a control's efficacy is shown.

| Family | Attack | Control |
|---|---|---|
| prompt injection | hostile content induces a victim | content sanitizer + moderator |
| collusion | mutual-vouch reputation ring | coordination detector |
| honeypot | reconnaissance probing | decoy trap (passive detection) |
| scam | non-delivery fraud | escrow refund |
| abuse | abusive forum posts | content moderation |
| adaptive / cross-tactic | pivots technique when blocked | per-technique watcher |

## Analysis lenses

All read the event stream (disk or in-memory):

* per-run: `evaluate.py` (verdict, threat / defense-efficacy / residual-risk,
  findings), `dashboard.py` (HTML), `evidence.py` (markdown + JSON package).
* per-suspect: `forensics.py` (incident case files; `campaign` portfolio).
* temporal: `trajectory.py` (per-round activity; under-defended rounds).
* comparative: `compare.py` (configs), `adaptive.compare_defenders`,
  `matrix.py` (defender x repertoire), `trials.py` (rates + Wilson CIs, sweep).
* coverage / efficacy: `coverage.py` (techniques a defense covers),
  `ablation.py` (risk reduction per control).
* enforcement: `gate.py` (pass/fail policy, nonzero exit), `suite.py`
  (behavioral battery + scorecard + family coverage).

## Surfaces

* CLI: `python -m src.range <subcommand>` (`list` enumerates everything).
* Library: `from src.range import ...` (curated API in `__init__.py`).

## Modes and determinism

`OBSCURA_MODE=range` enables the research plane (records, durable logs, replay,
dashboards) and, with `OBSCURA_DIAG=1`, the ops-plane per-hop trace spans.
Default `public` writes nothing and changes no behaviour. Scripted and adaptive
runs are deterministic given a seed; real-model runs are made reproducible by
recording and replaying responses (`llm_io.py`).

## How to extend

* **New policy / behaviour**: implement `decide(obs) -> Action`; drop it into a
  cast. No engine change.
* **New action**: add a branch in `_apply` that emits the right events, and add
  the kind to `ACTIONS`. Unknown kinds are recorded as `tool.misuse`.
* **New cast / scenario**: add a builder and register it in `agents.CASTS`
  (runnable via `--cast`) and/or add a `SuiteCase` to `suite.DEFAULT_SUITE`
  (tag its threat `family`).
* **New event kind**: define it in `scenario.py`; analysis tools pick it up via
  the shared stream.

## Scope

Real autonomous models run in the range today; their recorded decisions live in
`tests/fixtures/real_runs/` and replay deterministically
(`tests/test_real_model_replay.py`), so real agent behaviour is captured and
regression-tested without a key. The live ops-plane trace exercise exists as a
runnable harness (`tests/test_range_live.py`). The remaining frontier is scale
(larger casts, more models) and a live multi-machine network for ops-plane
traces.
