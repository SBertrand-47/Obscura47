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


def _probe_ws_reachable(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Best-effort TCP probe of a peer's WebSocket port.

    Returns ``(ok, detail)``. ``ok=True`` means a TCP connection
    completed within ``timeout``; ``False`` means the port refused or
    timed out. A passing TCP probe doesn't prove the WS upgrade or auth
    handshake will succeed, but a failing one is conclusive proof the
    peer cannot be used as a hop, which is what diagnose was missing.
    """
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, ""
    except socket.timeout:
        return False, "timed out"
    except OSError as e:
        return False, str(e) or e.__class__.__name__
    except Exception as e:
        return False, f"{e.__class__.__name__}: {e}"


def run_diagnostics(address: str | None = None) -> DiagnosticReport:
    """Run the registry/HS lookup walk and return a structured report.

    Imports are deferred so this module is cheap to import from the GUI
    even when the user never triggers a diagnostic.
    """
    from src.utils.config import REGISTRY_URL
    from src.utils.onion_addr import is_obscura_address, normalize_obscura_input
    from src.core.internet_discovery import (
        registry_request_json,
        RegistryHTTPError,
        fetch_peers_from_registry,
        is_self_peer,
        is_public_internet_host,
    )

    # Accept the same shapes a user is likely to paste from a browser
    # (``http://x.obscura/``, ``x.obscura:80``). The display address keeps
    # the user's original input so they can see what was parsed; downstream
    # checks use the bare hostname.
    address = normalize_obscura_input(address) if address else address
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

    # 2a. Private-IP peers. A relay registered on an RFC1918 address is
    # only useful inside that LAN; off-LAN clients and hosts cannot
    # reach it, so picking it as rv/intro silently breaks dials. Doesn't
    # block the dial (peers may legitimately serve same-LAN traffic) but
    # surfaces the risk loudly.
    private_peers = [
        p for p in peers
        if p.get("host") and not is_public_internet_host(p["host"])
        and not is_self_peer(p)
    ]
    public_count = len([p for p in peers if is_public_internet_host(p.get("host"))])
    if private_peers:
        labels = [f"{p['host']}:{p.get('port')}" for p in private_peers]
        report.steps.append(DiagnosticStep(
            name="Public-routable peers",
            ok=public_count > 0,
            summary=(
                f"{public_count} public, {len(private_peers)} private-IP peer(s)"
            ),
            detail=(
                "These peers are heartbeating the registry on private IPs, so "
                "they are only reachable inside that LAN. Picking one as a "
                "rendezvous or intro point silently breaks .obscura dials "
                "from hosts on a different network (rv_join from the host "
                "never lands). Private-IP peers: " + ", ".join(labels)
            ),
        ))

    # 2b. Peer WS reachability. Catches the case the registry calls a
    # peer alive (HTTP heartbeat works) but its WS port is firewalled
    # or its WS server never bound - the dominant silent-failure mode
    # for .obscura dials, since every circuit through such a peer dies
    # on a 15s handshake timeout.
    probe_targets = [p for p in peers if p.get("ws_port") and not is_self_peer(p)]
    if probe_targets:
        reachable: list[str] = []
        unreachable: list[str] = []
        for p in probe_targets:
            ok, why = _probe_ws_reachable(p["host"], p["ws_port"], timeout=3.0)
            label = f"{p['host']}:{p['ws_port']}"
            if ok:
                reachable.append(label)
            else:
                unreachable.append(f"{label} ({why})")
        if unreachable:
            report.steps.append(DiagnosticStep(
                name="Peer WS reachability",
                ok=False,
                summary=f"{len(reachable)}/{len(probe_targets)} WS ports reachable",
                detail=(
                    "These peers heartbeat the registry but their WebSocket "
                    "port doesn't accept TCP from this machine. Circuits "
                    "that pick them will time out (~15s) and .obscura dials "
                    "may fail even when the registry says everything is "
                    "fine. Unreachable: " + ", ".join(unreachable)
                ),
            ))
        else:
            report.steps.append(DiagnosticStep(
                name="Peer WS reachability",
                ok=True,
                summary=f"all {len(reachable)} WS ports reachable",
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

    # 5. End-to-end rendezvous dial.
    #
    # The descriptor-level checks above only confirm the host is *publishing*
    # and that its intro points appear in the live peer list. They do not
    # prove a dialer can actually splice an rv circuit with the host - and
    # we have seen real-world cases where they cannot, e.g. the host
    # advertises an intro on an RFC1918 LAN address, the host's intro-WS
    # idle-closed so reverse_data has no path back, or the host process
    # exited inside the descriptor's 1-hour TTL window.
    #
    # We attempt a real dial with an ephemeral keypair so the diagnostic
    # exercises the same code path as the browser-driven dial and surfaces
    # those failures explicitly.
    _append_rendezvous_step(report, address, intros)
    return report


def _append_rendezvous_step(
    report: "DiagnosticReport",
    address: str,
    intros: list[dict],
) -> None:
    import time
    from src.core.rendezvous import dial_hidden_service, close_hs

    try:
        from Crypto.PublicKey import ECC
        priv = ECC.generate(curve="P-256")
        pub_pem = priv.public_key().export_key(format="PEM")
    except Exception as e:
        report.steps.append(DiagnosticStep(
            name="Rendezvous dial",
            ok=False,
            summary=f"could not generate ephemeral key: {e}",
        ))
        return

    timeout = 12.0
    t0 = time.monotonic()
    try:
        dialed = dial_hidden_service(address, pub_pem, ready_timeout=timeout)
    except Exception as e:
        report.steps.append(DiagnosticStep(
            name="Rendezvous dial",
            ok=False,
            summary=f"raised {type(e).__name__}: {e}",
        ))
        return
    elapsed = time.monotonic() - t0

    if not dialed:
        from src.core.internet_discovery import is_private_peer
        lan_intros = [
            f"{p.get('host')}:{p.get('port')}"
            for p in intros if is_private_peer(p)
        ]
        causes = [
            "the host process exited while its descriptor was still within "
            "the 1-hour TTL (the descriptor lookup above only proves the "
            "descriptor exists, not that the host is currently alive)",
            "the host's intro-point WS channel idle-closed, so reverse_data "
            "frames from the intro point have no path back to the host - "
            "the host's republish loop normally re-establishes within ~50s",
            "the descriptor advertises an intro on a network address that "
            "is not reachable from this dialer (e.g. an RFC1918 LAN IP)",
        ]
        detail = (
            "The introduce + rv_ready handshake did not complete within "
            f"{timeout:.0f}s. Common causes: "
            + "; ".join(f"({chr(ord('a')+i)}) {c}" for i, c in enumerate(causes))
            + "."
        )
        if lan_intros:
            detail += (
                "\n\nThis descriptor currently advertises intro point(s) on a "
                "private LAN address: " + ", ".join(lan_intros) + ". External "
                "dialers cannot reach those, so any rotation onto them will "
                "fail. Cause (c) is the most likely fit here."
            )
        report.steps.append(DiagnosticStep(
            name="Rendezvous dial",
            ok=False,
            summary=f"rv_ready timeout after {elapsed:.1f}s",
            detail=detail,
        ))
        return

    # Success - tear the rendezvous circuit down so we don't leak it.
    route, rv_req_id, _ = dialed
    try:
        close_hs(route, rv_req_id)
    except Exception:
        pass
    report.steps.append(DiagnosticStep(
        name="Rendezvous dial",
        ok=True,
        summary=f"introduce + rv_ready completed in {elapsed:.1f}s",
    ))


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
