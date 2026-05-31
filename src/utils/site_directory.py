"""Discovery surface: list the live `.obscura` sites the registry knows about.

The registry already tracks every published hidden-service descriptor and
exposes them via ``GET /hs/list`` (addr + expiry + last-refresh time). This
module turns that into a browsable listing for the desktop/tray apps, and
optionally enriches each entry with the site's self-published
``/.well-known/obscura.json`` manifest (title/description/tags) when the
network is reachable.

Manifest enrichment is best-effort: it routes through the local proxy like
any other `.obscura` fetch, so it only works while connected and is allowed
to fail silently per-site (the address still shows, just without a title).
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
