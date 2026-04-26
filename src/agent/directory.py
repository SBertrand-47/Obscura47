"""Optional discovery surface for `.obscura` hidden services.

An opt-in directory that sites register with by publishing a
``/.well-known/obscura.json`` manifest at their own address.  The
directory periodically fetches manifests and maintains an in-memory
listing that any visitor can query.

Wire surface (mounted via :class:`~src.agent.tools.ToolRegistry`):

* ``register(address: string)``  — tell the directory about a site.
* ``unregister(address: string)`` — remove a listing (caller must own it).
* ``list(query?: string, limit?: int)`` — search / browse listings.
* ``get(address: string)`` — fetch details for a single listing.
* Topic ``listings`` — SSE stream of register / unregister events.

Persistence is optional (``--state`` flag for JSON file).

Public framing: opt-in directory for `.obscura` hidden-service
discovery.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.agent.app import AgentApp, Request, Response
from src.agent.client import AgentClient
from src.agent.runtime import AgentRuntime
from src.agent.tools import ParamSpec, ToolError, ToolRegistry
from src.utils.logger import get_logger
from src.utils.onion_addr import is_obscura_address

if TYPE_CHECKING:
    from src.agent.observatory import Observer

log = get_logger(__name__)

DIRECTORY_PROTOCOL_VERSION = "obscura.directory/1"
SITE_MANIFEST_PROTOCOL_VERSION = "obscura.site/1"
SITE_MANIFEST_PATH = "/.well-known/obscura.json"
MAX_LISTINGS = 10_000
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_TITLE_LEN = 120
MAX_DESCRIPTION_LEN = 500


@dataclass
class Listing:
    address: str
    title: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)
    registered_by: str = ""
    registered_at: float = 0.0
    last_seen: float = 0.0


class DirectoryState:
    """Thread-safe in-memory directory of `.obscura` sites."""

    def __init__(self, state_path: str | None = None):
        self._lock = threading.Lock()
        self._listings: dict[str, Listing] = {}
        self._state_path = state_path
        if state_path and os.path.isfile(state_path):
            self._load(state_path)

    def register(
        self,
        address: str,
        caller: str,
        title: str = "",
        description: str = "",
        tags: list[str] | None = None,
    ) -> Listing:
        if not is_obscura_address(address):
            raise ValueError(f"invalid .obscura address: {address}")
        if len(self._listings) >= MAX_LISTINGS and address not in self._listings:
            raise ValueError("directory is full")
        now = time.time()
        with self._lock:
            existing = self._listings.get(address)
            if existing and existing.registered_by and existing.registered_by != caller:
                raise PermissionError("listing owned by another caller")
            listing = Listing(
                address=address,
                title=(title or "")[:MAX_TITLE_LEN],
                description=(description or "")[:MAX_DESCRIPTION_LEN],
                tags=(tags or [])[:10],
                registered_by=caller,
                registered_at=existing.registered_at if existing else now,
                last_seen=now,
            )
            self._listings[address] = listing
            self._persist()
        return listing

    def unregister(self, address: str, caller: str) -> bool:
        with self._lock:
            listing = self._listings.get(address)
            if not listing:
                return False
            if listing.registered_by and listing.registered_by != caller:
                raise PermissionError("listing owned by another caller")
            del self._listings[address]
            self._persist()
        return True

    def get(self, address: str) -> Listing | None:
        with self._lock:
            return self._listings.get(address)

    def search(self, query: str = "", limit: int = DEFAULT_LIMIT) -> list[Listing]:
        limit = min(max(1, limit), MAX_LIMIT)
        q = query.lower()
        with self._lock:
            results = []
            for listing in sorted(
                self._listings.values(),
                key=lambda l: l.last_seen,
                reverse=True,
            ):
                if q and q not in listing.address.lower() and q not in listing.title.lower() and q not in listing.description.lower() and not any(q in t.lower() for t in listing.tags):
                    continue
                results.append(listing)
                if len(results) >= limit:
                    break
        return results

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._listings)

    def _persist(self):
        if not self._state_path:
            return
        data = {
            addr: {
                "address": l.address,
                "title": l.title,
                "description": l.description,
                "tags": l.tags,
                "registered_by": l.registered_by,
                "registered_at": l.registered_at,
                "last_seen": l.last_seen,
            }
            for addr, l in self._listings.items()
        }
        tmp = self._state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self._state_path)

    def _load(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for addr, d in data.items():
                self._listings[addr] = Listing(
                    address=d["address"],
                    title=d.get("title", ""),
                    description=d.get("description", ""),
                    tags=d.get("tags", []),
                    registered_by=d.get("registered_by", ""),
                    registered_at=d.get("registered_at", 0),
                    last_seen=d.get("last_seen", 0),
                )
        except Exception as exc:
            log.warning("Failed to load directory state: %s", exc)


def _listing_dict(l: Listing) -> dict[str, Any]:
    return {
        "address": l.address,
        "title": l.title,
        "description": l.description,
        "tags": l.tags,
        "registered_at": l.registered_at,
        "last_seen": l.last_seen,
    }


def _clean_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if not isinstance(tags, list):
        raise ValueError("manifest tags must be an array of strings")
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in tags:
        if not isinstance(raw, str):
            raise ValueError("manifest tags must be an array of strings")
        tag = raw.strip()
        if not tag or tag in seen:
            continue
        cleaned.append(tag[:40])
        seen.add(tag)
        if len(cleaned) >= 10:
            break
    return cleaned


def normalize_site_manifest(address: str, manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    manifest_address = manifest.get("address")
    if manifest_address and manifest_address != address:
        raise ValueError("manifest address does not match requested address")
    protocol = manifest.get("protocol")
    if protocol and protocol != SITE_MANIFEST_PROTOCOL_VERSION:
        raise ValueError(f"unsupported manifest protocol: {protocol}")
    title = manifest.get("title", "")
    description = manifest.get("description", "")
    if title is not None and not isinstance(title, str):
        raise ValueError("manifest title must be a string")
    if description is not None and not isinstance(description, str):
        raise ValueError("manifest description must be a string")
    return {
        "title": (title or "").strip()[:MAX_TITLE_LEN],
        "description": (description or "").strip()[:MAX_DESCRIPTION_LEN],
        "tags": _clean_tags(manifest.get("tags")),
    }


def fetch_site_manifest(
    address: str,
    client: AgentClient | None = None,
) -> dict[str, Any]:
    client = client or AgentClient()
    resp = client.get(address, SITE_MANIFEST_PATH)
    if not resp.ok:
        raise ValueError(
            f"manifest fetch returned HTTP {resp.status} for {address}{SITE_MANIFEST_PATH}"
        )
    try:
        manifest = resp.json()
    except ValueError as e:
        raise ValueError(f"manifest was not valid JSON: {e}")
    return normalize_site_manifest(address, manifest)


class DirectoryClient:
    """Convenience client for talking to a directory hidden service."""

    def __init__(
        self,
        addr: str,
        *,
        port: int = 80,
        agent: AgentClient | None = None,
    ):
        self.addr = addr
        self.port = int(port)
        self.agent = agent or AgentClient()

    def register(self, address: str) -> dict[str, Any]:
        return self.agent.call_tool(
            self.addr,
            "register",
            {"address": address},
            port=self.port,
        )

    def unregister(self, address: str) -> dict[str, Any]:
        return self.agent.call_tool(
            self.addr,
            "unregister",
            {"address": address},
            port=self.port,
        )

    def list(
        self,
        *,
        query: str = "",
        limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"limit": limit}
        if query:
            args["query"] = query
        return self.agent.call_tool(
            self.addr,
            "list",
            args,
            port=self.port,
        )

    def get(self, address: str) -> dict[str, Any]:
        return self.agent.call_tool(
            self.addr,
            "get",
            {"address": address},
            port=self.port,
        )


def build_directory_app(
    state_path: str | None = None,
    observer: "Observer | None" = None,
    manifest_fetcher: Any | None = None,
) -> tuple[AgentApp, ToolRegistry]:
    app = AgentApp()
    tools = ToolRegistry()
    state = DirectoryState(state_path=state_path)

    if observer:
        app.observer = observer
        tools.observer = observer

    listings_topic = tools.topic("listings")

    @tools.tool(
        "register",
        description="Register or update a .obscura site in the directory by fetching its manifest.",
        params=[
            ParamSpec("address", "string", required=True, description=".obscura address to list"),
        ],
        returns="object",
    )
    def handle_register(args: dict, req: Request) -> dict:
        caller = req.caller_fingerprint
        if not caller:
            raise ToolError("authentication_required", "caller identity unknown")
        fetcher = manifest_fetcher or fetch_site_manifest
        try:
            manifest = fetcher(args["address"])
        except ValueError as e:
            raise ToolError("bad_manifest", str(e))
        except Exception as e:
            raise ToolError("manifest_unavailable", str(e) or repr(e))
        try:
            listing = state.register(
                address=args["address"],
                caller=caller,
                title=manifest.get("title", ""),
                description=manifest.get("description", ""),
                tags=manifest.get("tags"),
            )
        except (ValueError, PermissionError) as e:
            raise ToolError("register_failed", str(e))
        event = {"action": "register", **_listing_dict(listing)}
        listings_topic.publish(event)
        return _listing_dict(listing)

    @tools.tool(
        "unregister",
        description="Remove a .obscura site from the directory.",
        params=[
            ParamSpec("address", "string", required=True, description=".obscura address to remove"),
        ],
        returns="object",
    )
    def handle_unregister(args: dict, req: Request) -> dict:
        caller = req.caller_fingerprint
        if not caller:
            raise ToolError("authentication_required", "caller identity unknown")
        try:
            removed = state.unregister(args["address"], caller)
        except PermissionError as e:
            raise ToolError("permission_denied", str(e))
        if not removed:
            raise ToolError("not_found", "listing not found")
        event = {"action": "unregister", "address": args["address"]}
        listings_topic.publish(event)
        return {"removed": True, "address": args["address"]}

    @tools.tool(
        "list",
        description="Search or browse .obscura site listings.",
        params=[
            ParamSpec("query", "string", required=False, description="search query (matches address, title, description, tags)"),
            ParamSpec("limit", "int", required=False, description=f"max results (default {DEFAULT_LIMIT}, max {MAX_LIMIT})"),
        ],
        returns="object",
    )
    def handle_list(args: dict, req: Request) -> dict:
        results = state.search(
            query=args.get("query", ""),
            limit=args.get("limit", DEFAULT_LIMIT),
        )
        return {
            "count": len(results),
            "total": state.count,
            "listings": [_listing_dict(l) for l in results],
        }

    @tools.tool(
        "get",
        description="Get details for a single .obscura listing.",
        params=[
            ParamSpec("address", "string", required=True, description=".obscura address"),
        ],
        returns="object",
    )
    def handle_get(args: dict, req: Request) -> dict:
        listing = state.get(args["address"])
        if not listing:
            raise ToolError("not_found", "listing not found")
        return _listing_dict(listing)

    tools.mount(app)

    @app.get("/")
    def index(req: Request) -> Response:
        return Response(
            200,
            body=json.dumps({
                "service": "directory.obscura",
                "protocol": DIRECTORY_PROTOCOL_VERSION,
                "listings": state.count,
            }),
            content_type="application/json",
        )

    return app, tools


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.agent.directory",
        description="Run an opt-in .obscura directory service.",
    )
    parser.add_argument("--name", default="directory", help="service name")
    parser.add_argument("--key", default=None, help="service key path")
    parser.add_argument("--state", default=None, help="JSON state file for persistence")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--observatory", default=None)
    parser.add_argument("--observatory-jsonl", default=None)

    from src.agent.sandboxed_runtime import add_sandbox_arguments, policy_from_args
    add_sandbox_arguments(parser)
    args = parser.parse_args(argv)

    from src.agent.observatory import build_observer_from_flags
    observer = build_observer_from_flags(
        actor=args.name,
        remote_addr=args.observatory,
        jsonl_path=args.observatory_jsonl,
    )

    from src.utils.sites import load_or_create_site_key
    _priv, _pub, key_path, _created = load_or_create_site_key(
        name=args.name, key=args.key,
    )

    policy = policy_from_args(args)
    app, _tools = build_directory_app(state_path=args.state, observer=observer)
    runtime = AgentRuntime(
        name=args.name,
        key_path=key_path,
        app=app,
        bind_host=args.bind,
        bind_port=args.port,
        observer=observer,
        policy=policy,
    )

    if not runtime.start():
        print("[directory] failed to publish hidden service", file=sys.stderr)
        return 1

    print(f"[directory] {runtime.name} → {runtime.address} (local {runtime.local_url})")
    try:
        runtime.join()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
