# Observability Design

> Status: design / in progress. This document is the contract the
> observability layer is built against. It formalizes pieces that already
> exist in the codebase and names the small amount of connective tissue still
> missing. **Nothing here changes routing behavior or the public product.**

## Why this exists

Obscura47's long-term goal is an *observability-first adversarial network for
AI agents* - "a dark web for agents, but fully observable." The current
network (registry, relays/exits, transport, ECDSA auth, multi-hop onion
routing, NAT traversal, `.obscura` services) is the **infrastructure layer**.
This document covers the **observability layer** that turns that infrastructure
into an instrument for studying agent behavior - without regressing the
consumer anonymity network.

## One tool: `python -m src.range`

The whole range is driven from a single entry point. `run` is the turnkey path
(execute a scenario, score it, optionally emit a dashboard); the rest dispatch
to focused tools.

```
python -m src.range run --kind readiness
python -m src.range run --kind adaptive --defender weak --rounds 10
OBSCURA_MODE=range python -m src.range run --kind agents --dashboard
OBSCURA_MODE=range python -m src.range run --kind agents --llm-roles attacker,defender
python -m src.range report   <experiment_id>
python -m src.range evaluate <experiment_id>
python -m src.range dashboard <experiment_id> -o run.html
python -m src.range compare
```

## Core decision: two planes, kept apart

Telemetry is split into two planes that must never be merged. Mixing them makes
later experiments unanalyzable.

### Ops plane - "is the network healthy?"
- **Primitive (exists today):** `src/utils/diag.py` `diag.emit(event, **fields)`,
  plus `src/utils/logger.py` and `src/utils/audit.py`.
- **Gate:** `OBSCURA_DIAG` (local JSONL) / `OBSCURA_DIAG_REGISTRY` (registry POST).
  Off by default; `emit()` is a no-op when disabled (`diag.py:170`).
- **Already out-of-band:** ships to the registry `/diag` endpoint, NOT over the
  overlay it measures. Keep it that way.
- **Tracks:** heartbeats, join/disconnect, circuit build success/fail, hop
  latency, throughput, retries, drops, auth failures, queue depth, guardrail
  triggers, version/OS distribution.

### Research plane - "what are the agents doing?"
- **Primitive (exists today):** `src/agent/observatory.py` `Observer`/`Event`/
  sinks (`Null`/`Memory`/`Jsonl`/`Multi`/`Remote`) + collector app; plus
  `src/agent/ledger.py` (fake-money transactions) and `src/agent/directory.py`.
- **Gate:** observer wiring; `NullSink` discards when absent.
- **Tracks:** agent identity (currently key fingerprint), action lineage,
  target service, action category, success/fail, tx amounts, trust/reputation
  deltas, tools used, messages, policy violations, coordination, deception.

**Rule:** ops plane lives in `core/` and never imports the research plane.
Research plane lives in `agent/`. Neither edits routing logic to *serve*
observability - they only *emit from* it.

## Two modes

A single switch decides how much of the above is live. Read once in
`src/utils/config.py` as `OBSCURA_MODE`.

| Mode | Value | Behavior |
|---|---|---|
| **Public** (default) | `public` | Today's product. Research plane absent. Ops diag off unless an operator explicitly opts in. Consumer anonymity intact, zero added attack surface. |
| **Range** | `range` | Operator runs the whole closed world. Full ops + research instrumentation, experiment records, replay. God-view is legitimate because nothing leaks back to the studied agents. |

Public-mode builds must carry zero research-plane cost. Range mode is opt-in
and operator-only.

## Connective tissue

These are the only genuinely new pieces. All are additive and inert in public mode.

1. **Experiment context.** ✅ *Implemented* - `src/utils/experiment.py`.
   `OBSCURA_MODE` (`public`/`range`) in `config.py`; an immutable
   `ExperimentRecord` (`experiment_id`, `started_at`, `ended_at`,
   `code_commit_sha`, `topology_snapshot`, `agent_config`, `agent_prompt_hash`,
   `model_id`, `policy_version`, `random_seed`, `guardrail_config_hash`,
   `extra`) persisted under `~/.obscura47/experiments/`. `experiment_id` is
   stamped on every event in BOTH planes - `Event.experiment_id` (research) and
   `diag.emit` records (ops). Source: `OBSCURA_EXPERIMENT_ID` env or
   `start_experiment(...)`. Inert in public mode (`current_experiment_id()`
   returns `None`). Query the research plane by run via
   `observatory query experiment_id=…`.

2. **Trace context across hops.** ✅ *Implemented* - `src/utils/trace.py`.
   A small `trace` block rides in-band in the tunnel/HS envelope (which
   `forward_message` already re-encrypts hop-by-hop). The origin (`start_tunnel`)
   emits `trace.start`; each relay (`node.py` tunnel + HS forward) emits
   `hop.forward` and rewrites the parent pointer + `hop_index`; the exit emits
   `trace.terminal`. Each span carries `trace_id` (= the circuit `request_id`),
   `span_id`, `parent_span_id`, `hop_index`, forming the tree
   `agent → relay A → relay B → exit`. Emitted through `diag`, so spans inherit
   the `experiment_id` stamp and out-of-band shipping. **Operator-only:** a hard
   no-op unless BOTH range mode AND diag are on, so public-mode frames never
   carry a correlatable token and no path is ever revealed.
   Hidden-service dials are traced too: `dial_hidden_service` stamps the
   rendezvous circuit (`trace.start kind=hs_dial`), relays emit `hop.forward`,
   and the rendezvous point emits `trace.terminal role=rendezvous` -- the same
   span tree as exit tunnels, for `.obscura` traffic.
   The agent-app `session_id` ↔ network `request_id` bridge is also wired: the
   agent client puts its session on the (local) CONNECT as `X-Obscura-Session`,
   the proxy extracts it and `start_tunnel` records it in the circuit's
   `trace.start` span. The header rides only the loopback CONNECT, never the
   overlay, so an agent's logical session ties to its network path in the
   operator-only plane without weakening anonymity. Trace coverage is now
   complete for both clearnet tunnels and hidden-service circuits.

3. **Research-plane egress out-of-band in range mode.** ✅ *Implemented*.
   `RemoteSink` still ships over the overlay for the public observatory product,
   but a new `HttpSink` POSTs event batches directly to an operator collector
   (`OBSCURA_RESEARCH_COLLECTOR_URL`, optional `OBSCURA_RESEARCH_COLLECTOR_TOKEN`
   via an `X-Obscura-Research-Token` header), bypassing the overlay the way
   `diag` POSTs to the registry `/diag`. `build_observer_from_flags` **refuses
   the overlay `RemoteSink` in range mode** and steers to the out-of-band
   collector, so research telemetry never travels the paths under study. Both
   sinks share a `_BufferedSink` base (bounded queue + batching worker +
   drop-oldest backpressure).

## Suggested external stack (don't hand-build)

OpenTelemetry Collector → Prometheus (metrics) / Loki (logs) / Tempo (per-hop
traces) / Grafana (dashboards); append-only store (e.g. Postgres) for agent
actions, transactions, reputation, replay. Low-cardinality labels only - no raw
IPs / request IDs / circuit IDs as Prometheus/Loki labels (put those in
structured fields). Default to pseudonymous IDs, hashed circuit IDs, redacted
payloads; payload capture off unless an experiment requires it.

## Choke points (already mapped)

Ops-plane emit points already exist or are one-liners at known locations
(circuit build, per-hop forward, stream open/close, descriptor publish/lookup,
rendezvous, exit connect, ECDSA auth result, guardrail denial, peer
heartbeat/health, errors/retries). Most success/failure paths already log;
known gaps: HS frame relay forward, ECDSA auth internals, per-IP/concurrent
tunnel limit denials (429/503 unlogged), tunnel-multiplex demux, HS session
close, successful descriptor lookups.

## Readiness gate before live agents

Run a deterministic ~10-scripted-actor simulation (browser, HS host, buyer,
seller, fake bank, escrow, malicious actor, defender, moderator, one unstable
node). The telemetry alone must answer: which nodes were online; which routes
failed; which hop caused latency; which agent initiated each action; which
services were visited; which transactions occurred; which guardrails fired; can
the run be replayed/reconstructed. Only then introduce autonomous agents.

✅ *Implemented (research plane)* - `src/range/scenario.py`. Drives the ten
scripted actors through a coherent storyline (host a market, list goods, buy
via escrow, build trust, attempt a scam, get flagged and moderated) using the
real `Observer` + `LedgerState`, fully in-process. Every action is a
research-plane event stamped with the run's `experiment_id`;
`readiness_report()` reconstructs the answers purely by querying the collector.
Run it with `OBSCURA_MODE=range python -m src.range.scenario`. The two
network-path questions (which route failed, which hop was slow) are ops-plane
and need a live multi-hop network; the report names them as out of scope here
rather than silently omitting them. Next: add live-network actors so those
ops-plane questions are answered by real `trace` spans too.

## Decision-loop agents (real-model-ready)

✅ *Implemented* - `src/range/agents.py`. The architectural unlock: instead of a
hardcoded storyline, each agent receives a partial `Observation` of the world
each round and returns an `Action` through a pluggable `Policy`. The world
applies the action and emits the same research events, so `report`/`evaluate`/
`compare` work unchanged.

* `ScriptedPolicy` - deterministic, observation-driven behaviour per role;
  what the tests and reproducible runs use. Behaviour is emergent, not
  scripted: e.g. an attacker's phishing slips past a defender that has not yet
  learned the signature, then is flagged the next round once learned, and the
  moderator bans on observing the flag.
* `LLMPolicy` - asks a Claude model to choose the action (tool-forced
  structured output, prompt-cached system prompt). A true drop-in: the engine
  is identical. It activates only when the `anthropic` SDK and
  `ANTHROPIC_API_KEY` are present, so it never affects imports or the
  deterministic path. `anthropic` is an optional dependency
  (`pip install anthropic`), intentionally not in `requirements.txt`.

`default_cast(policy_factory=...)` swaps real models in for some or all roles.
This is the seam that turns the simulator into a place to study real
autonomous agents; putting a live model behind one role is now a config change,
not a code change.

## Adaptive adversary (multi-round)

✅ *Implemented* - `src/range/adaptive.py`. Where the scripted scenario shows
the plumbing, this shows agents that *adapt over time*. An attacker works
through a repertoire of techniques (escalating to a new one whenever the
current is caught); a defender detects techniques it already knows and learns
each new one after it slips through once. Emergent cat-and-mouse: a weak
defender suffers a string of breaches before the attacker's repertoire is
exhausted and contained; a strong defender contains from round one; a passive
defender never contains. Every round emits the standard research-plane event
kinds, so `report`/`evaluate`/`compare` work on adaptive runs unchanged. Fully
deterministic. Run: `OBSCURA_MODE=range python -m src.range.adaptive --rounds 10
--defender weak`. `compare_defenders()` (`--compare`) ranks the defender models
(strong / learning / weak / passive) by breaches suffered and time-to-
containment: the "which defensive policy held up best over time?" leaderboard.

## Dashboard

✅ *Implemented* - `src/range/dashboard.py`. Composes the reconstruction and the
scored evaluation into a single self-contained HTML page (verdict badge, score
bars, severity-ranked findings, timeline, transactions, trust standings,
adversarial investigation chain). No server, no JavaScript, no external
dependencies, all values HTML-escaped. This is the "fully observable" thesis
made visible. Run: `OBSCURA_MODE=range python -m src.range.dashboard
<experiment_id> -o run.html`.

## Reconstruction / replay

✅ *Implemented* - `src/range/report.py`. Range runs persist an append-only
research-event log at `experiment.events_path(experiment_id)`
(`~/.obscura47/experiments/<id>.events.jsonl`), colocated with the immutable
run record. `python -m src.range.report <experiment_id>` reconstructs the whole
run *from storage alone* (independent of the live process): timeline, per-agent
activity, the fake economy's transactions, trust rebuilt from the deltas, the
adversarial attack -> detection -> response chain, and a per-suspect
investigation view. This is the replayability the vision hinges on, and the
seed of the operator dashboard. Public mode persists nothing to disk, so the
consumer environment is never written to.

## Evaluation / evidence package

✅ *Implemented (first cut)* - `src/range/evaluate.py`. Scores a run from its
event stream into the assessment a safety/security team would actually consume:
threat level, defense efficacy (detection + containment rates), residual risk,
a verdict (`contained` / `detected_not_fully_contained` / `uncontained` /
`no_adversarial_activity`), per-attacker outcomes (detected? latency? banned?),
financial integrity (value reaching banned actors), severity-ranked findings,
and an executive summary. The score always references the immutable run record
(commit, model, seed, policy version), so it is tied to a known configuration.
Scoring is generic over any run; the readiness scenario is the deterministic
fixture. Run: `OBSCURA_MODE=range python -m src.range.evaluate <experiment_id>`.

**Tool-misuse and prompt-injection signals** ✅ The engine enforces
authorization: an agent that acts while banned, or reaches for a privilege it
does not hold (e.g. a non-moderator banning someone), emits a `tool.misuse`
event and the effect is refused. The evaluator counts misuse (weighted heavily
in threat), raises a HIGH finding per reason, and tracks prompt-injection
attempts and *exposure* (attempts whose author was never detected). These are
the agent-safety signals a real LLM agent is most likely to trip.

**Model/policy comparison** ✅ *Implemented* - `src/range/compare.py`. The
scenario is parameterized by a `Profile` (the subject under test: attacker
aggression, defender competence, whether moderation acts). `compare()` runs a
panel of profiles, scores each, and ranks them into a leaderboard by residual
risk - the "same task, several subjects, who handled the adversary best" view.
The default panel spans baseline, aggressive-attacker, slow-defender,
no-moderation, and weak-defender; `weak-defender` surfaces as `uncontained`
(worst), demonstrating the comparison. Run: `python -m src.range.compare`.
Still to build toward the full package: prompt-injection / tool-misuse signals,
and route/service graphs (ops plane).

## Enterprise framing (for later)

Wedge product = "Obscura47 Agent Security Range": a fully observable adversarial
range for testing long-horizon autonomous-agent behavior before deployment.
Lead with the agent-evaluation problem, not "anonymous network" / "dark web."
Deliverable to a buyer is an evaluation/evidence package (risk score,
model-to-model comparison, full session replay, decision timeline, policy
violations, prompt-injection exposure, tool-misuse, route/service graphs,
defensive-control outcomes, reproducible config, exec summary).
