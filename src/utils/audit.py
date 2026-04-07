import json
import os
import threading
import time
import uuid


_LOCKS: dict[str, threading.Lock] = {}
_LAST_PRUNE: dict[str, float] = {}
_PRUNE_INTERVAL_SECONDS = 300.0


def _get_lock(path: str) -> threading.Lock:
    lock = _LOCKS.get(path)
    if lock is None:
        lock = threading.Lock()
        _LOCKS[path] = lock
    return lock


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _prune_locked(path: str, retention_days: int) -> None:
    if retention_days <= 0:
        return

    now = time.time()
    last_prune = _LAST_PRUNE.get(path, 0.0)
    if now - last_prune < _PRUNE_INTERVAL_SECONDS:
        return

    cutoff = now - (retention_days * 86400)
    tmp_path = f"{path}.tmp"
    kept = 0

    try:
        with open(path, "r", encoding="utf-8") as src, open(tmp_path, "w", encoding="utf-8") as dst:
            for line in src:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue
                ts = record.get("ts", 0)
                if ts >= cutoff:
                    dst.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
                    kept += 1
        os.replace(tmp_path, path)
        _LAST_PRUNE[path] = now
    except FileNotFoundError:
        _LAST_PRUNE[path] = now
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def write_audit_event(
    path: str,
    event: dict,
    *,
    enabled: bool = True,
    retention_days: int = 14,
) -> None:
    """Append a JSONL audit event and periodically prune expired records.

    The caller controls the privacy boundary by deciding which fields belong in
    `event`. This helper intentionally does not enrich records with network or
    identity metadata.
    """
    if not enabled or not path:
        return

    record = {
        "event_id": uuid.uuid4().hex,
        "ts": time.time(),
        **event,
    }

    _ensure_parent_dir(path)
    lock = _get_lock(path)
    with lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        _prune_locked(path, retention_days)
