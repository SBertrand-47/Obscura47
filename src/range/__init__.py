"""Obscura47 agent research range: a public API over the range modules.

A curated surface so the range can be driven programmatically, not only via the
`python -m src.range` CLI. Run a scenario, score / analyse it, or drive agents
with a model -- all from one import. See ``src/range/README.md``.
"""

from src.range.ablation import measure as ablation_efficacy
from src.range.adaptive import (
    AttackerModel, DefenderModel, compare_defenders, run_adaptive)
from src.range.agents import (
    Action, Agent, LLMPolicy, Observation, Policy, ScriptedPolicy,
    decision_trace, default_cast, run_world, society_cast, total_llm_usage)
# Aliased to avoid shadowing the same-named submodules on the package.
from src.range.compare import compare as compare_configs
from src.range.coverage import probe as coverage_probe
from src.range.crossplane import correlate as correlate_planes
from src.range.dashboard import render_html as render_dashboard
from src.range.evaluate import build_evaluation, evaluate_run
from src.range.evidence import build_evidence
from src.range.forensics import build_incidents, campaign, incidents_from_events
from src.range.gate import check_gate
from src.range.live import (
    LiveAgent, LiveDefender, LiveEscrow, LiveInvestigator, LiveModelDefender,
    LiveModerator, LiveRegulator, LiveReputationGate, LiveSession,
    ReputationLedger, run_society)
from src.range.llm_io import (
    RecordingClient, ReplayClient, load_recording, save_recording)
from src.range.matrix import risk_matrix
from src.range.report import build_report
from src.range.scenario import Profile, run_scenario
from src.range.security_report import build_comparison, build_report_card
from src.range.suite import run_suite
from src.range.trajectory import build_trajectory, under_defended_rounds
from src.range.trials import injection_susceptibility_sweep, run_trials

__all__ = [
    # run
    "run_scenario", "run_adaptive", "run_world", "default_cast",
    "society_cast", "Profile", "AttackerModel", "DefenderModel",
    # agents / policies
    "Agent", "Observation", "Action", "Policy", "ScriptedPolicy", "LLMPolicy",
    "decision_trace", "total_llm_usage",
    # model record/replay
    "RecordingClient", "ReplayClient", "save_recording", "load_recording",
    # score / analyse
    "build_evaluation", "evaluate_run", "build_report", "build_incidents",
    "incidents_from_events", "campaign", "build_trajectory",
    "under_defended_rounds", "check_gate", "build_evidence",
    "render_dashboard",
    # compare / sweep / audit
    "compare_configs", "compare_defenders", "risk_matrix", "run_trials",
    "injection_susceptibility_sweep", "coverage_probe", "ablation_efficacy",
    # battery
    "run_suite",
    # deliverable
    "build_report_card", "build_comparison",
    # cross-plane observability
    "correlate_planes",
    # live bridge: agents on the real overlay
    "LiveSession", "LiveAgent", "LiveDefender", "LiveModelDefender",
    "LiveEscrow", "LiveReputationGate", "LiveModerator", "LiveInvestigator",
    "LiveRegulator", "ReputationLedger", "run_society",
]
