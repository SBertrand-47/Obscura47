"""Discovery surface: list the `.obscura` sites the registry knows about, and
verify which are actually reachable.

The registry tracks every published hidden-service descriptor and exposes them
via ``GET /hs/list`` (addr + expiry + last-refresh time). That is the
*published* set. It does NOT prove a site is reachable: a host can go cold while
its descriptor lingers, so a published address can be completely dead.

So this module keeps two notions strictly separate:

* **published** - has a (non-expired) descriptor in the registry. Cheap, but
  only means "was published," not "is up."
* **live** - we just dialed it over the overlay and the host answered. This is
  the only honest "live", and it requires being connected. :func:`probe_site_live`
  performs that dial; any HTTP response (even an error status) proves the
  rendezvous completed and the host is up. A timeout or rendezvous failure means
  published-but-not-responding.

Manifest enrichment (title/description) is separate and best-effort.
"""

from __future__ import annotations

import time
from typing import Any

from src.utils.logger import get_logger

log = get_logger(__name__)


def fetch_live_sites(*, timeout: int = 10) -> list[dict[str, Any]]:
    """Return live HS descriptors from the registry, freshest first.

    Each entry is ``{"addr", "expires", "updated"}``. Raises whatever
    :func:`registry_request_json` raises on transport/HTTP failure so the
    caller can surface a clear "couldn't reach the registry" message.
    """
    from src.core.internet_discovery import registry_request_json
    from src.utils.config import REGISTRY_URL

    rows = registry_request_json(f"{REGISTRY_URL}/hs/list", timeout=timeout)
    if not isinstance(rows, list):
        return []
    sites: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict) and row.get("addr"):
            sites.append({
                "addr": row["addr"],
                "expires": row.get("expires"),
                "updated": row.get("updated"),
            })
    return sites


def probe_site_live(addr: str, *, prober: Any | None = None,
                    timeout: float = 12.0) -> dict[str, Any]:
    """Verify a `.obscura` site is reachable RIGHT NOW by dialing it.

    Returns ``{"addr", "live": bool, "status"/"error"}``. The rule is
    deliberately conservative and honest: ``live`` is True only if the dial
    returns *some* HTTP response, which proves the rendezvous completed and the
    host answered. ANY status counts (a 404 still means the host is up). A
    timeout or rendezvous failure - the cold-host / dead-intro case - yields
    ``live: False``. A registry descriptor alone never makes a site live.

    Requires the local proxy/overlay to be up; if it is not, every probe fails
    and sites should be shown as "unverified", not "not responding". ``prober``
    is injectable for tests: a callable ``addr -> http_status`` (raising on
    unreachable).
    """
    if prober is None:
        def prober(a: str) -> int:
            from src.agent.client import AgentClient
            return AgentClient(timeout=timeout).get(a, "/").status
    try:
        status = prober(addr)
        return {"addr": addr, "live": True, "status": int(status)}
    except Exception as e:  # noqa: BLE001 - any failure means "not reachable now"
        return {"addr": addr, "live": False, "error": type(e).__name__}


def enrich_with_manifests(
    sites: list[dict[str, Any]],
    *,
    limit: int = 25,
    fetcher: Any | None = None,
) -> list[dict[str, Any]]:
    """Best-effort: attach ``title``/``description``/``tags`` from each site's
    ``/.well-known/obscura.json``. Requires proxy connectivity; failures are
    swallowed per-site so the address still lists. Only the first ``limit``
    sites are probed (manifest fetches are slow, routed over circuits).
    """
    if fetcher is None:
        from src.agent.directory import fetch_site_manifest as fetcher  # type: ignore

    for site in sites[:limit]:
        try:
            manifest = fetcher(site["addr"])
        except Exception as e:
            log.debug("manifest fetch failed for %s: %s", site["addr"], e)
            continue
        if isinstance(manifest, dict):
            site["title"] = (manifest.get("title") or "").strip()
            site["description"] = (manifest.get("description") or "").strip()
            site["tags"] = manifest.get("tags") or []
    return sites


def _format_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "just now"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 36:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def format_site_listing(
    sites: list[dict[str, Any]],
    *,
    now: float | None = None,
) -> str:
    """Render fetched (optionally enriched) sites as a human-readable block.

    Pure/string-only so it is unit-testable without network or a GUI.
    """
    if not sites:
        return ("No live .obscura sites are currently published to the "
                "registry.\n\nIf you're hosting one, make sure it's running "
                "and connected.")
    now = time.time() if now is None else now
    lines: list[str] = [f"{len(sites)} live .obscura site(s):", ""]
    for site in sites:
        addr = site.get("addr", "?")
        title = (site.get("title") or "").strip()
        header = f"{title}  ({addr})" if title else addr
        lines.append(header)
        desc = (site.get("description") or "").strip()
        if desc:
            lines.append(f"  {desc[:160]}")
        updated = site.get("updated")
        if isinstance(updated, (int, float)):
            lines.append(f"  last seen: {_format_age(now - updated)}")
        lines.append("")
    return "\n".join(lines).rstrip()
