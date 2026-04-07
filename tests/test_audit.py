import json
import time

from src.utils.audit import write_audit_event


def test_write_audit_event_appends_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"

    write_audit_event(str(path), {"event": "sample", "component": "test"})

    with open(path, "r", encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    assert len(rows) == 1
    assert rows[0]["event"] == "sample"
    assert rows[0]["component"] == "test"
    assert "event_id" in rows[0]
    assert "ts" in rows[0]


def test_write_audit_event_prunes_expired_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    old_ts = time.time() - (20 * 86400)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"event_id": "old", "ts": old_ts, "event": "old"}) + "\n")

    write_audit_event(str(path), {"event": "fresh"}, retention_days=14)

    with open(path, "r", encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    assert len(rows) == 1
    assert rows[0]["event"] == "fresh"
