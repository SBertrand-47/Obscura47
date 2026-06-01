"""Structured diagnostic event log for cross-node debugging.

Off by default. Two opt-in switches, intended for development on your own
network:

* ``OBSCURA_DIAG=1`` - append each event as JSONL to
  ``~/.obscura47/logs/{role}.jsonl`` (rolled at ~10MB, one-deep).
* ``OBSCURA_DIAG_REGISTRY=1`` - also POST each event to the registry's
  ``/diag`` endpoint so events from every node land in one timeline.
  Requires ``OBSCURA_DIAG_TOKEN`` to be the same value on every emitting
  node and on the registry.

This is a privacy regression - events name who picked which peer, which
exit a request hit, which intro a host published. Production deployments
must leave it off. Use only when you own the network and you're trying
to diagnose flaky behaviour across multiple machines.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from typing import Any

# Imported for its side effect: running _load_dotenv() so OBSCURA_DIAG*
# values from the project's .env file are visible to our os.environ reads
# even when diag is imported by a script that bypasses the node/exit
# entry points (e.g. tests or the diag-tail CLI).
from src.utils import config as _config  # noqa: F401

DIAG_DIR = os.path.join(os.path.expanduser("~"), ".obscura47", "logs")
MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB before rolling
SEND_QUEUE_MAX = 1000              # cap memory if registry is slow/unreachable
SEND_BATCH_SIZE = 32
SEND_FLUSH_SECONDS = 2.0
SEND_HTTP_TIMEOUT = 4.0


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


_role: str = "unknown"
_node_id: str = "self"  # registration overwrites with real peer_id
_lock = threading.Lock()
_send_queue: "queue.Queue[dict] | None" = None
_send_thread: threading.Thread | None = None


def set_role(role: str) -> None:
    """Identify this process for subsequent emit() calls."""
    global _role
    _role = str(role)


def set_node_id(node_id: str | None) -> None:
    """Set the peer_id learned at registration so events can be correlated."""
    global _node_id
    if node_id:
        _node_id = str(node_id)


def is_enabled() -> bool:
    return _env_truthy("OBSCURA_DIAG") or _env_truthy("OBSCURA_DIAG_REGISTRY")


# ── Local JSONL writer ────────────────────────────────────────────

def _local_path() -> str:
    return os.path.join(DIAG_DIR, f"{_role}.jsonl")


def _roll_if_needed(path: str) -> None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size < MAX_FILE_BYTES:
        return
    rolled = path + ".1"
    try:
        if os.path.exists(rolled):
            os.remove(rolled)
        os.rename(path, rolled)
    except OSError:
        # Best-effort: if rotation fails, fall through and keep appending.
        pass


def _write_local(record: dict) -> None:
    try:
        os.makedirs(DIAG_DIR, mode=0o700, exist_ok=True)
        path = _local_path()
        with _lock:
            _roll_if_needed(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        # Diag failures must never break the calling code path.
        pass


# ── Registry POST worker ──────────────────────────────────────────

def _send_loop():
    assert _send_queue is not None
    from src.utils.config import REGISTRY_URL
    token = os.environ.get("OBSCURA_DIAG_TOKEN", "").strip()
    if not token:
        # Without a token, the registry will reject every POST. Drain the
        # queue silently rather than burning CPU on rejected requests.
        while True:
            try:
                _send_queue.get(timeout=10.0)
            except queue.Empty:
                continue
    url = f"{REGISTRY_URL.rstrip('/')}/diag"

    while True:
        batch: list[dict] = []
        try:
            batch.append(_send_queue.get(timeout=SEND_FLUSH_SECONDS))
        except queue.Empty:
            continue
        # Drain any waiting events up to SEND_BATCH_SIZE.
        while len(batch) < SEND_BATCH_SIZE:
            try:
                batch.append(_send_queue.get_nowait())
            except queue.Empty:
                break
        body = json.dumps({"events": batch}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Diag-Token": token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=SEND_HTTP_TIMEOUT) as resp:
                resp.read()  # drain
        except Exception:
            # Drop the batch on failure rather than retry-looping - the
            # local JSONL still has these events for offline analysis.
            pass


def _ensure_send_thread() -> None:
    global _send_queue, _send_thread
    if _send_thread is not None and _send_thread.is_alive():
        return
    _send_queue = queue.Queue(maxsize=SEND_QUEUE_MAX)
    _send_thread = threading.Thread(
        target=_send_loop, name="diag-sender", daemon=True,
    )
    _send_thread.start()


# ── Public API ────────────────────────────────────────────────────

def emit(event: str, **fields: Any) -> None:
    """Record a diagnostic event. Cheap no-op when diag is disabled."""
    if not is_enabled():
        return
    record = {
        "ts": time.time(),
        "role": _role,
        "node_id": _node_id,
        "event": event,
    }
    # Stamp the active experiment so ops-plane events are attributable to a
    # run. Empty in public mode, so the record shape is unchanged there.
    from src.utils import experiment as _experiment
    record.update(_experiment.experiment_fields())
    if fields:
        # JSON-safe coercion: stringify anything urllib/json can't serialise.
        safe = {}
        for k, v in fields.items():
            try:
                json.dumps(v)
                safe[k] = v
            except (TypeError, ValueError):
                safe[k] = repr(v)
        record["fields"] = safe

    if _env_truthy("OBSCURA_DIAG"):
        _write_local(record)
    if _env_truthy("OBSCURA_DIAG_REGISTRY"):
        _ensure_send_thread()
        assert _send_queue is not None
        try:
            _send_queue.put_nowait(record)
        except queue.Full:
            # Drop oldest, push newest - newer events are more diagnostic.
            try:
                _send_queue.get_nowait()
                _send_queue.put_nowait(record)
            except (queue.Empty, queue.Full):
                pass
