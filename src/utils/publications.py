"""Publication ledger - what this agent has put on the network, and is it up?

Every time this machine publishes a `.obscura` site it records a
*publication*: the address, the local target it fronts, the manifest it
advertises, which directories it is registered in, and the last time the
site was verified reachable end to end (a real rendezvous dial, not just
"the descriptor exists"). This is the agent's own answer to "what have I
published, when, and can the world still reach it right now?"

The record is keyed by `.obscura` address - the stable identity of a
publication. The human-facing name can change and the local target can
move, but the address is derived from the service key and never does, so
it is the join key across re-publishes.

Stored as a single JSON file at ``~/.obscura47/publications.json``,
rewritten atomically on every change (write-temp-then-``os.replace``) so a
crash mid-write cannot corrupt the ledger. Each mutation is a full
load-modify-store so independent short-lived processes (the host loop, a
``host status`` check) converge instead of clobbering each other.

This module owns no network or key material; it is pure bookkeeping. The
host path calls :func:`record_publish` when a site goes up,
:func:`record_directory` / :func:`record_unregister` track directory
listings, and :func:`record_reachability` stamps the result of a
reachability probe. :func:`check_reachability` is the convenience that
runs the probe (via :mod:`src.utils.diagnose`) and stamps the result in
one call.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.utils.diagnose import DiagnosticReport

PUBLICATIONS_PATH = os.path.join(
    os.path.expanduser("~"), ".obscura47", "publications.json"
)

# Bump if the on-disk shape changes in a non-additive way.
PUBLICATIONS_VERSION = 1


@dataclass
class DirectoryListing:
    """A directory this publication is registered in."""

    address: str
    registered_at: float = 0.0


@dataclass
class Publication:
    """One `.obscura` site this machine has published.

    ``reachable`` is tri-state: ``None`` means never checked, ``True`` /
    ``False`` is the result of the most recent reachability probe at
    ``last_checked_at``. ``last_reachable_at`` is the last time the probe
    actually succeeded, which survives a later transient failure so the
    operator can see "it was up 3 minutes ago".
    """

    address: str
    name: str = ""
    target: str | None = None
    title: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    first_published_at: float = 0.0
    last_published_at: float = 0.0
    directories: list[DirectoryListing] = field(default_factory=list)
    last_checked_at: float | None = None
    reachable: bool | None = None
    last_reachable_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["directories"] = [asdict(d) for d in self.directories]
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Publication":
        dirs = []
        for d in raw.get("directories") or []:
            if isinstance(d, dict) and d.get("address"):
                dirs.append(DirectoryListing(
                    address=str(d["address"]),
                    registered_at=float(d.get("registered_at", 0.0)),
                ))
        return cls(
            address=str(raw["address"]),
            name=str(raw.get("name", "")),
            target=raw.get("target"),
            title=str(raw.get("title", "")),
            description=str(raw.get("description", "")),
            tags=[str(t) for t in (raw.get("tags") or [])],
            first_published_at=float(raw.get("first_published_at", 0.0)),
            last_published_at=float(raw.get("last_published_at", 0.0)),
            directories=dirs,
            last_checked_at=_opt_float(raw.get("last_checked_at")),
            reachable=_opt_bool(raw.get("reachable")),
            last_reachable_at=_opt_float(raw.get("last_reachable_at")),
        )


def _opt_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _opt_bool(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _load(path: str) -> dict[str, Publication]:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    raw = data.get("publications") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return {}
    out: dict[str, Publication] = {}
    for entry in raw:
        if not isinstance(entry, dict) or not entry.get("address"):
            continue
        try:
            pub = Publication.from_dict(entry)
        except (KeyError, ValueError, TypeError):
            continue
        out[pub.address] = pub
    return out


def _store(path: str, pubs: dict[str, Publication]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    snapshot = {
        "version": PUBLICATIONS_VERSION,
        "publications": [
            p.to_dict()
            for p in sorted(pubs.values(), key=lambda p: p.first_published_at)
        ],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def record_publish(
    address: str,
    *,
    name: str = "",
    target: str | None = None,
    title: str | None = None,
    description: str | None = None,
    tags: list[str] | None = None,
    path: str = PUBLICATIONS_PATH,
    now: float | None = None,
) -> Publication:
    """Record that ``address`` is published (idempotent upsert).

    ``first_published_at`` is set once and preserved across re-publishes;
    ``last_published_at`` is bumped every call. Manifest fields
    (``title`` / ``description`` / ``tags``) are only overwritten when a
    non-``None`` value is supplied, so re-hosting without a manifest does
    not wipe a previously recorded one.
    """
    if not address:
        raise ValueError("address is required to record a publication")
    now = time.time() if now is None else now
    pubs = _load(path)
    pub = pubs.get(address)
    if pub is None:
        pub = Publication(address=address, first_published_at=now)
        pubs[address] = pub
    pub.last_published_at = now
    if not pub.first_published_at:
        pub.first_published_at = now
    if name:
        pub.name = name
    if target is not None:
        pub.target = target
    if title is not None:
        pub.title = title
    if description is not None:
        pub.description = description
    if tags is not None:
        pub.tags = list(tags)
    _store(path, pubs)
    return pub


def record_directory(
    address: str,
    directory_addr: str,
    *,
    path: str = PUBLICATIONS_PATH,
    now: float | None = None,
) -> Publication | None:
    """Note that ``address`` was registered in directory ``directory_addr``.

    Returns the updated publication, or ``None`` if the address is not
    tracked yet (directory registration without a prior publish record is
    a no-op rather than inventing a half-empty entry).
    """
    now = time.time() if now is None else now
    pubs = _load(path)
    pub = pubs.get(address)
    if pub is None:
        return None
    for d in pub.directories:
        if d.address == directory_addr:
            d.registered_at = now
            break
    else:
        pub.directories.append(
            DirectoryListing(address=directory_addr, registered_at=now)
        )
    _store(path, pubs)
    return pub


def record_unregister(
    address: str,
    directory_addr: str,
    *,
    path: str = PUBLICATIONS_PATH,
) -> Publication | None:
    """Drop ``directory_addr`` from ``address``'s directory listings."""
    pubs = _load(path)
    pub = pubs.get(address)
    if pub is None:
        return None
    pub.directories = [d for d in pub.directories if d.address != directory_addr]
    _store(path, pubs)
    return pub


def record_reachability(
    address: str,
    reachable: bool,
    *,
    path: str = PUBLICATIONS_PATH,
    now: float | None = None,
) -> Publication | None:
    """Stamp the result of a reachability probe onto ``address``."""
    now = time.time() if now is None else now
    pubs = _load(path)
    pub = pubs.get(address)
    if pub is None:
        return None
    pub.last_checked_at = now
    pub.reachable = bool(reachable)
    if reachable:
        pub.last_reachable_at = now
    _store(path, pubs)
    return pub


def get(address: str, *, path: str = PUBLICATIONS_PATH) -> Publication | None:
    return _load(path).get(address)


def all_publications(*, path: str = PUBLICATIONS_PATH) -> list[Publication]:
    """Every tracked publication, newest publish last."""
    return sorted(_load(path).values(), key=lambda p: p.last_published_at)


def remove(address: str, *, path: str = PUBLICATIONS_PATH) -> bool:
    pubs = _load(path)
    if address not in pubs:
        return False
    del pubs[address]
    _store(path, pubs)
    return True


def check_reachability(
    address: str,
    *,
    path: str = PUBLICATIONS_PATH,
    record: bool = True,
) -> tuple[bool, "DiagnosticReport"]:
    """Probe ``address`` end to end and (optionally) stamp the result.

    Runs the full registry -> descriptor -> live-intro -> rendezvous-dial
    walk from :func:`src.utils.diagnose.run_diagnostics`; the publication
    is considered reachable iff every step passes (``report.ok``). When
    ``record`` is set the verdict is written to the ledger so a later
    ``host published`` reflects it. Returns ``(reachable, report)`` so the
    caller can also surface *why* a probe failed.

    An *inconclusive* report (``report.inconclusive`` - this machine has no
    rendezvous relay distinct from the host's intro point) is never
    recorded as a hard failure: the site may well be reachable from another
    vantage, so stamping ``reachable=False`` would be a lie. The prior
    verdict is left untouched.
    """
    from src.utils.diagnose import run_diagnostics

    report = run_diagnostics(address)
    reachable = report.ok
    if record and not report.inconclusive:
        record_reachability(address, reachable, path=path)
    return reachable, report
