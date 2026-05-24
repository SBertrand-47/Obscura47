"""Connection diagnostics shared by the CLI and the desktop/tray apps.

Walks the same path a user's traffic takes when opening a `.obscura`
address - registry health, live peers, descriptor endpoint shape, full
verified descriptor - and returns a structured report. The GUI renders
it in a modal; the CLI pretty-prints it.

Kept as plain data (dataclasses + a string formatter) so the GUI does
not need to depend on tkinter-incompatible imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DiagnosticStep:
    name: str
    ok: bool
    summary: str
    detail: str | None = None


@dataclass
class DiagnosticReport:
    registry_url: str
    address: str | None
    steps: list[DiagnosticStep] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    @property
    def first_failure(self) -> DiagnosticStep | None:
        for s in self.steps:
            if not s.ok:
                return s
        return None


def run_diagnostics(address: str | None = None) -> DiagnosticReport:
    """Run the registry/HS lookup walk and return a structured report.

    Imports are deferred so this module is cheap to import from the GUI
    even when the user never triggers a diagnostic.
    """
    from src.utils.config import REGISTRY_URL
    from src.utils.onion_addr import is_obscura_address
    from src.core.internet_discovery import (
        registry_request_json,
        RegistryHTTPError,
        fetch_peers_from_registry,
    )

    report = DiagnosticReport(registry_url=REGISTRY_URL, address=address)

    # 1. Registry health
    try:
        h = registry_request_json(f"{REGISTRY_URL}/health", timeout=10)
        report.steps.append(DiagnosticStep(
            name="Registry health",
            ok=True,
            summary=f"reachable - peers={h.get('peers')} {h.get('breakdown', {})}",
        ))
    except RegistryHTTPError as e:
        report.steps.append(DiagnosticStep(
            name="Registry health",
            ok=False,
            summary=f"unreachable [{e.kind}]",
            detail=str(e),
        ))
        return report

    # 2. Live peers
    peers = fetch_peers_from_registry() or []
    nodes = [p for p in peers if p.get("role") == "node"]
    exits = [p for p in peers if p.get("role") == "exit"]
    no_peers = not nodes and not exits
    report.steps.append(DiagnosticStep(
        name="Live peers",
        ok=not no_peers,
        summary=f"nodes={len(nodes)} exits={len(exits)}",
        detail=(
            "No relays or approved exits are online. Hosted sites need at "
            "least one approved exit (or, for .obscura traffic, at least "
            "one relay) heartbeating against this registry."
        ) if no_peers else None,
    ))

    if not address:
        return report

    if not is_obscura_address(address):
        report.steps.append(DiagnosticStep(
            name="Address shape",
            ok=False,
            summary=f"{address!r} is not a valid .obscura address",
        ))
        return report

    # 3. HS descriptor endpoint shape
    try:
        registry_request_json(
            f"{REGISTRY_URL}/hs/descriptor/{address}", timeout=10,
        )
        report.steps.append(DiagnosticStep(
            name="Descriptor endpoint",
            ok=True,
            summary="JSON response",
        ))
    except RegistryHTTPError as e:
        if e.kind == "http_status" and e.status == 404:
            report.steps.append(DiagnosticStep(
                name="Descriptor endpoint",
                ok=False,
                summary="404 - no descriptor for this address",
                detail=(
                    "The registry knows about /hs/descriptor but has no "
                    "current descriptor for this address. The host may be "
                    "offline or has not published yet."
                ),
            ))
            return report
        if e.kind == "content_type":
            report.steps.append(DiagnosticStep(
                name="Descriptor endpoint",
                ok=False,
                summary=f"non-JSON response ({e.content_type})",
                detail=(
                    "The deployed registry is missing the /hs/descriptor "
                    "route and a reverse proxy is serving a fallback page. "
                    "The registry needs to be redeployed with current "
                    "registry_server.py to add hidden-service support."
                ),
            ))
            return report
        report.steps.append(DiagnosticStep(
            name="Descriptor endpoint",
            ok=False,
            summary=f"failed [{e.kind}]",
            detail=str(e),
        ))
        return report

    # 4. Full verified descriptor fetch
    from src.core.rendezvous import fetch_descriptor

    desc = fetch_descriptor(address)
    if not desc:
        report.steps.append(DiagnosticStep(
            name="Verified descriptor",
            ok=False,
            summary="descriptor verification failed",
            detail=(
                "The registry returned a descriptor but it failed signature "
                "or schema verification. See the log for details."
            ),
        ))
        return report
    intros = desc.get("intro_points") or []
    if not intros:
        report.steps.append(DiagnosticStep(
            name="Verified descriptor",
            ok=False,
            summary="no intro points - host offline",
        ))
        return report

    intro_keys = {(p.get("host"), p.get("port")) for p in intros}
    live_keys = {(p.get("host"), p.get("port")) for p in peers}
    overlap = intro_keys & live_keys
    if overlap:
        report.steps.append(DiagnosticStep(
            name="Verified descriptor",
            ok=True,
            summary=f"{len(overlap)}/{len(intros)} intro points currently live",
        ))
    else:
        report.steps.append(DiagnosticStep(
            name="Verified descriptor",
            ok=False,
            summary="none of the intro points are live",
            detail=(
                "The descriptor advertises intro points but none of them are "
                "currently in the registry's live peer list. The host "
                "machine may be offline."
            ),
        ))
    return report


def format_report_text(report: DiagnosticReport) -> str:
    """Render a report as plain text suitable for a console or modal."""
    lines = [f"Registry: {report.registry_url}"]
    if report.address:
        lines.append(f"Address:  {report.address}")
    lines.append("")
    for step in report.steps:
        mark = "✓" if step.ok else "✗"
        lines.append(f"  {mark} {step.name}: {step.summary}")
        if step.detail:
            for chunk in _wrap(step.detail, width=72):
                lines.append(f"      {chunk}")
    lines.append("")
    if report.ok:
        lines.append("All checks passed.")
    else:
        first = report.first_failure
        if first:
            lines.append(f"First failure: {first.name} - {first.summary}")
    return "\n".join(lines)


def _wrap(text: str, *, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width=width) or [text]
