"""Experiment context for the research telemetry plane.

The long-term goal is an *observability-first adversarial network for AI
agents*: a closed world where autonomous agents act and the operator can
reconstruct exactly what happened. To study a run scientifically you must be
able to group every event by the experiment it belongs to and, later, replay
that run from an immutable record of how it was configured.

This module is the single source of the current ``experiment_id`` and the
per-run record. Both telemetry planes stamp the active ``experiment_id`` onto
their events:

* the **ops plane** (``src/utils/diag.py``) - "is the network healthy?"
* the **research plane** (``src/agent/observatory.py``) - "what did agents do?"

It is deliberately inert outside range mode. In ``public`` mode
:func:`current_experiment_id` always returns ``None``, so events are stamped
exactly as before and the consumer network carries zero research-plane cost.
See ``docs/observability.md`` for the full design.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from src.utils import config

EXPERIMENTS_DIR = os.path.join(
    os.path.expanduser("~"), ".obscura47", "experiments"
)

_lock = threading.Lock()
_current_id: str | None = None
_env_resolved = False


@dataclass(frozen=True)
class ExperimentRecord:
    """Immutable description of one experiment run, sufficient to replay it.

    Created once at the start of a run and never mutated except to stamp
    ``ended_at`` when the run finishes. Everything needed to answer "why did
    the agents behave this way, and can we reproduce it?" lives here.
    """

    experiment_id: str
    started_at: float
    ended_at: float | None = None
    code_commit_sha: str | None = None
    topology_snapshot: Any = None
    agent_config: Any = None
    agent_prompt_hash: str | None = None
    model_id: str | None = None
    policy_version: str | None = None
    random_seed: int | None = None
    guardrail_config_hash: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Current-experiment accessors ──────────────────────────────────

def current_experiment_id() -> str | None:
    """The experiment_id stamped on events, or ``None`` outside range mode.

    Resolves ``OBSCURA_EXPERIMENT_ID`` lazily on first use so a range run can
    be tagged purely from the environment without calling
    :func:`start_experiment`. Always ``None`` in public mode, which keeps the
    consumer network provably unaffected.
    """
    global _current_id, _env_resolved
    if not config.IS_RANGE_MODE:
        return None
    with _lock:
        if _current_id is None and not _env_resolved:
            _env_resolved = True
            env = os.environ.get("OBSCURA_EXPERIMENT_ID", "").strip()
            if env:
                _current_id = env
        return _current_id


def experiment_fields() -> dict[str, str]:
    """Fields to merge into a telemetry record. Empty dict when inactive."""
    eid = current_experiment_id()
    return {"experiment_id": eid} if eid else {}


def set_experiment_id(experiment_id: str | None) -> None:
    """Set (or clear) the active experiment_id. No-op in public mode."""
    global _current_id, _env_resolved
    if not config.IS_RANGE_MODE:
        return
    with _lock:
        _current_id = str(experiment_id) if experiment_id else None
        _env_resolved = True


def new_experiment_id() -> str:
    return uuid.uuid4().hex[:16]


# ── Run records ───────────────────────────────────────────────────

def _git_commit_sha() -> str | None:
    """Best-effort current commit, for reproducibility. Never raises."""
    env = os.environ.get("OBSCURA_CODE_COMMIT_SHA", "").strip()
    if env:
        return env
    try:
        repo_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        sha = out.stdout.strip()
        return sha or None
    except Exception:
        return None


def _record_path(experiment_id: str) -> str:
    return os.path.join(EXPERIMENTS_DIR, f"{experiment_id}.json")


def events_path(experiment_id: str) -> str:
    """Canonical append-only research-event log for a run, colocated with its
    record. Replay/analysis tools read this back to reconstruct the run."""
    return os.path.join(EXPERIMENTS_DIR, f"{experiment_id}.events.jsonl")


def _write_record(record: ExperimentRecord) -> None:
    """Persist a record atomically. Never raises (telemetry must not break)."""
    try:
        os.makedirs(EXPERIMENTS_DIR, mode=0o700, exist_ok=True)
        path = _record_path(record.experiment_id)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2, default=repr)
        os.replace(tmp, path)
    except Exception:
        pass


def start_experiment(
    experiment_id: str | None = None,
    *,
    topology_snapshot: Any = None,
    agent_config: Any = None,
    agent_prompt_hash: str | None = None,
    model_id: str | None = None,
    policy_version: str | None = None,
    random_seed: int | None = None,
    guardrail_config_hash: str | None = None,
    persist: bool = True,
    **extra: Any,
) -> ExperimentRecord | None:
    """Begin an experiment: build + persist the run record, set it active.

    Returns the record, or ``None`` in public mode (research plane absent).
    The record captures the current commit so the run can be reproduced later.
    """
    if not config.IS_RANGE_MODE:
        return None
    eid = str(experiment_id) if experiment_id else new_experiment_id()
    record = ExperimentRecord(
        experiment_id=eid,
        started_at=time.time(),
        code_commit_sha=_git_commit_sha(),
        topology_snapshot=topology_snapshot,
        agent_config=agent_config,
        agent_prompt_hash=agent_prompt_hash,
        model_id=model_id,
        policy_version=policy_version,
        random_seed=random_seed,
        guardrail_config_hash=guardrail_config_hash,
        extra=dict(extra),
    )
    set_experiment_id(eid)
    if persist:
        _write_record(record)
    return record


def finish_experiment(experiment_id: str | None = None) -> None:
    """Stamp ``ended_at`` on the run record and clear the active id.

    Reads back the persisted record so the immutable start-time fields are
    preserved; only ``ended_at`` is added. No-op in public mode.
    """
    if not config.IS_RANGE_MODE:
        return
    eid = experiment_id or current_experiment_id()
    if not eid:
        return
    path = _record_path(eid)
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        raw["ended_at"] = time.time()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2, default=repr)
        os.replace(tmp, path)
    except Exception:
        pass
    if not experiment_id or experiment_id == current_experiment_id():
        set_experiment_id(None)


def load_record(experiment_id: str) -> ExperimentRecord | None:
    """Load a persisted run record for replay/analysis, or ``None``."""
    try:
        with open(_record_path(experiment_id), "r", encoding="utf-8") as f:
            raw = json.load(f)
        return ExperimentRecord(**raw)
    except Exception:
        return None
