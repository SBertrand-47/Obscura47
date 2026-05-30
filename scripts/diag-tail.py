#!/usr/bin/env python3
"""Follow the Obscura47 diagnostic event stream.

Reads JSONL events from either the centralised registry file (default,
``~/.obscura47/diag.jsonl``) or a local per-role file (``--local node``)
and pretty-prints them. Useful when chasing intermittent failures across
multiple nodes - turn on OBSCURA_DIAG / OBSCURA_DIAG_REGISTRY on each
node and tail the merged stream here.

Usage:

    python scripts/diag-tail.py
    python scripts/diag-tail.py --local proxy
    python scripts/diag-tail.py --filter event=tunnel_closed
    python scripts/diag-tail.py --filter role=exit --filter event=origin_connect
    python scripts/diag-tail.py --no-follow            # one-shot dump

Filters are AND-combined. Each filter is ``key=value`` matching either a
top-level field (``role``, ``event``, ``node_id``) or a nested
``fields.X`` value (try ``--filter fields.ok=False``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Iterable


DEFAULT_REGISTRY_PATH = os.path.join(os.path.expanduser("~"), ".obscura47", "diag.jsonl")
DEFAULT_LOCAL_DIR = os.path.join(os.path.expanduser("~"), ".obscura47", "logs")


def _parse_filters(filters: Iterable[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for f in filters:
        if "=" not in f:
            print(f"warning: ignoring filter without '=': {f!r}", file=sys.stderr)
            continue
        k, v = f.split("=", 1)
        out.append((k.strip(), v.strip()))
    return out


def _get_path(record: dict, path: str):
    cur = record
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _matches(record: dict, filters: list[tuple[str, str]]) -> bool:
    for key, value in filters:
        actual = _get_path(record, key)
        if str(actual) != value:
            return False
    return True


def _format(record: dict) -> str:
    ts = record.get("ts") or record.get("received_at") or 0
    try:
        when = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S.%f")[:-3]
    except (TypeError, ValueError):
        when = str(ts)
    role = record.get("role", "?")
    node = record.get("node_id", "?")
    event = record.get("event", "?")
    fields = record.get("fields") or {}
    field_s = " ".join(f"{k}={v}" for k, v in fields.items())
    return f"{when} [{role:>6}] {node:<28} {event:<22} {field_s}"


def _tail(path: str, follow: bool, filters: list[tuple[str, str]]) -> None:
    if not os.path.exists(path):
        if not follow:
            print(f"no events: {path} does not exist", file=sys.stderr)
            return
        # Wait for the file to appear when following.
        while not os.path.exists(path):
            time.sleep(0.5)

    with open(path, "r", encoding="utf-8") as f:
        # Dump existing content first.
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _matches(record, filters):
                print(_format(record), flush=True)
        if not follow:
            return
        # Then follow new lines.
        while True:
            where = f.tell()
            line = f.readline()
            if not line:
                time.sleep(0.5)
                f.seek(where)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _matches(record, filters):
                print(_format(record), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Tail Obscura47 diagnostic events")
    parser.add_argument(
        "--local",
        metavar="ROLE",
        help=f"tail the local per-role file ({DEFAULT_LOCAL_DIR}/<role>.jsonl) instead of the registry feed",
    )
    parser.add_argument(
        "--path",
        help="explicit path to the JSONL file (overrides --local and default)",
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="key=value filter, repeatable. Supports dotted paths like fields.ok=False",
    )
    parser.add_argument(
        "--no-follow", action="store_true",
        help="dump existing events then exit",
    )
    args = parser.parse_args()

    if args.path:
        path = args.path
    elif args.local:
        path = os.path.join(DEFAULT_LOCAL_DIR, f"{args.local}.jsonl")
    else:
        path = DEFAULT_REGISTRY_PATH

    filters = _parse_filters(args.filter)
    try:
        _tail(path, follow=not args.no_follow, filters=filters)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
