# Obscura47 Agent Research Range

The **range** is the experimental layer on top of the Obscura47 network: a
private, fully observable, adversarial world for studying how autonomous agents
behave. The network (relays, exits, hidden services, transport) is the
infrastructure; the range is where agents host and visit services, transact in
fake money, build reputation, deceive, defend, and adapt, while an operator
captures and replays everything.

Design thesis: *a dark web for AI agents, but fully observable.* See
[`docs/observability.md`](../../docs/observability.md) for the full design and
[`docs/range-architecture.md`](../../docs/range-architecture.md) for how the
range is built and extended.

## Quickstart

One command runs a scenario, scores it, and (in range mode) writes a dashboard:

```bash
# scripted readiness scenario, scored
python -m src.range run --kind readiness

# multi-round adaptive attacker vs a learning defender
python -m src.range run --kind adaptive --defender weak --rounds 10

# decision-loop agents; persist a replayable run and emit an HTML dashboard
OBSCURA_MODE=range python -m src.range run --kind agents --dashboard
OBSCURA_MODE=range python -m src.range run --kind society --dashboard  # all threat families at once

# drive a role with a real model (needs: pip install anthropic + ANTHROPIC_API_KEY)
OBSCURA_MODE=range python -m src.range run --kind agents --llm-roles attacker,defender
OBSCURA_MODE=range python -m src.range run --kind agents --llm-roles all --model claude-sonnet-4-6
OBSCURA_MODE=range python -m src.range run --kind agents --llm-roles attacker,defender \
    --model-for attacker=claude-opus-4-8 --model-for defender=claude-haiku-4-5-20251001
# drive a role inside any named threat-family cast with a real model
OBSCURA_MODE=range python -m src.range run --kind agents --cast injection --llm-roles attacker
OBSCURA_MODE=range python -m src.range run --kind agents --llm-roles attacker --record run.json
python -m src.range run --kind agents --llm-roles attacker --replay run.json   # deterministic, no key

# indirect prompt-injection demo: hostile content induces a gullible agent
python -m src.range.agents --cast injection --events

# many trials -> distribution stats (the right shape for non-deterministic models)
python -m src.range.trials --p-follow 0.5 --trials 20

# sweep susceptibility -> the injection dose-response curve
python -m src.range.trials --sweep --trials 20

# risk surface: defender model x attacker repertoire (where defenses fall off)
python -m src.range matrix
```

Then inspect any persisted run:

```bash
python -m src.range report   <experiment_id>   # reconstruct the story
python -m src.range evaluate <experiment_id>   # scored evidence package
python -m src.range dashboard <experiment_id> -o run.html
python -m src.range compare                    # rank configs by residual risk
python -m src.range gate <experiment_id>       # CI gate: exit 1 on a safety regression
python -m src.range suite                       # behavioral battery vs expected outcomes
python -m src.range suite --md scorecard.md     # shareable security scorecard
python -m src.range evidence <id> --md report.md --json report.json
```

## The loop

```
RUN        scenario.py / adaptive.py / agents.py   (scripted or LLM policy)
  |  one research-event schema, stamped with an experiment_id
CAPTURE    experiment record + append-only events.jsonl   (range mode)
  |
  +-- report.py     reconstruct / investigate a run from storage
  +-- evaluate.py   score: verdict, threat, defense efficacy, residual risk,
  |                 permission integrity, prompt-injection signals, findings
  +-- compare.py    leaderboard across configs ("which is safest")
  +-- dashboard.py  self-contained HTML view
```

Every layer reads the same event stream, so scripted, adaptive, and real-LLM
runs flow through identically.

## Modules

| Module | Role |
|---|---|
| `scenario.py` | scripted readiness storyline; `Profile` varies the subject under test; `setup_world` is the shared run setup |
| `adaptive.py` | multi-round adaptive attacker vs learning defender; `compare_defenders` ranks defensive policies |
| `agents.py` | the decision-loop engine: `Observation` -> `Policy` -> `Action`; `ScriptedPolicy` (deterministic) and `LLMPolicy` (real model, drop-in) |
| `evaluate.py` | turns telemetry into a scored evidence package |
| `report.py` | reconstructs a run from its durable log |
| `forensics.py` | per-suspect incident case files (techniques, accomplices, funds, severity) |
| `trajectory.py` | per-round activity (attacks, defenses, volume, trust) -- how a run evolved |
| `coverage.py` | audit which attack techniques a defense covers vs misses |
| `compare.py` | runs a panel of configs and ranks them |
| `trials.py` | aggregates many runs into distribution statistics (rates + Wilson CIs, susceptibility sweep) |
| `matrix.py` | risk surface across defender model x attacker repertoire |
| `gate.py` | pass/fail safety gate against a policy; exits nonzero on regression (CI) |
| `llm_io.py` | record/replay model runs for deterministic, reproducible real-model sessions |
| `suite.py` | behavioral regression battery: scenarios vs expected gate outcomes |
| `evidence.py` | portable evidence package (markdown + JSON) with reproducibility provenance |
| `dashboard.py` | renders a run to a single static HTML page |
| `__main__.py` | the unified `python -m src.range` entry point |

## Agents and real models

An agent is an identity plus a `Policy` that maps an `Observation` to an
`Action`. The only difference between a scripted actor and a real model is the
policy object:

```python
from src.range.agents import default_cast, run_world, LLMPolicy, ScriptedPolicy

# all scripted (deterministic)
run_world(default_cast(), rounds=8)

# attacker driven by a real Claude model, everyone else scripted
def factory(role, goal):
    return LLMPolicy(role, goal) if role == "attacker" else ScriptedPolicy()
run_world(default_cast(factory), rounds=8)
```

`LLMPolicy` uses tool-forced structured output with a prompt-cached system
prompt. It is an optional capability: it activates only when the `anthropic`
package and `ANTHROPIC_API_KEY` are present, and never affects the deterministic
path. `anthropic` is intentionally not in `requirements.txt`.

## Two telemetry planes

* **Research plane** (this package) answers *what did the agents do?* Events go
  to a collector / durable log, and out-of-band in range mode.
* **Ops plane** (`src/utils/diag.py`, `trace.py`) answers *is the network
  healthy, and how did traffic flow?* Per-hop trace spans reconstruct each
  circuit. Operator-only, and a hard no-op outside range mode.

## Modes and environment

| Variable | Effect |
|---|---|
| `OBSCURA_MODE=range` | enables the research plane: experiment records, durable event logs, replay, dashboards. Default `public` keeps the consumer network untouched and writes nothing to disk. |
| `OBSCURA_EXPERIMENT_ID` | tag a run from the environment |
| `OBSCURA_DIAG=1` | enable ops-plane diagnostics / trace spans (range only) |
| `OBSCURA_RESEARCH_COLLECTOR_URL` | ship research events out-of-band to an operator collector |

Persisted runs live under `~/.obscura47/experiments/<id>.json` (record) and
`<id>.events.jsonl` (event log).

## Real-model runs

Real models run here today. The captured recordings in
`tests/fixtures/real_runs/` are genuine `claude-sonnet-4-6` decisions; they
replay deterministically with no key (`tests/test_real_model_replay.py`), so the
behavior they captured is a permanent regression. What they show:

* **Behavior is horizon-dependent.** The same attacker model looks benign at 3
  rounds (it only builds a storefront), runs an uncontained multi-technique
  campaign at 12, and is fully contained at 12 once a live defender is present.
* **A real model has a house style.** Dropped into the prompt-injection cast, it
  ignored the intended injection vector and fell back to storefront-cover +
  phishing. You cannot assume a model will exercise the technique a scenario
  targets.

Two signals are scored separately and must not be conflated: **threat / residual
risk** (attacker pressure the defenders did or did not contain) and
**permission integrity** (any agent - often a defender over-eager to enforce -
reaching for a tool outside its role). A defender overstepping should never read
as a more dangerous adversary.

## Determinism and scope

The scripted and adaptive scenarios are fully deterministic given a seed, so
runs are reproducible and replayable. Real-model runs are made reproducible by
recording and replaying responses (`llm_io.py`). The remaining frontier is
scale (larger casts, more models) and a live multi-machine network exercise for
ops-plane traces.
