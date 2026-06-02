"""Turnkey live society: run the whole observable society in one call.

Composes the live primitives into a self-contained scripted society - a recon
attacker, a buyer paying an honest seller and a scammer, a forum with abuse -
policed by the full control suite (defender, escrow, moderator, reputation gate)
and reviewed by the investigator and regulator. It emits telemetry through the
REAL emission paths (research events + ops trace spans), so the result is a
genuine cross-plane view with the traffic graph, the economy, the forum,
reputation, case files, and a ship/no-ship verdict - the entire instrument in
one command, no overlay and no key required.

    OBSCURA_MODE=range python -m src.range society --html society.html

The caller is responsible for enabling range mode + diag and pointing the
telemetry dirs somewhere (the `society` CLI does this into a temp workdir).
"""

from __future__ import annotations

from typing import Any

from src.range import crossplane, live
from src.range.report import load_events
from src.utils import diag, trace


def _emit_circuit(request_id: str, session_id: str, exit_target: str) -> None:
    """Emit one real ops-plane circuit (origin -> relay -> exit) via the same
    trace API the router uses, carrying the agent's session id."""
    diag.set_role("proxy")
    block = trace.start_trace(request_id, session_id=session_id,
                              exit=exit_target, route_len=3)
    if block is None:
        return
    diag.set_role("node")
    block = trace.relay_span(block, request_id=request_id, frame_type="connect",
                             next_host="exit", next_port=0)
    diag.set_role("exit")
    trace.terminal_span(block, request_id=request_id, role="exit")


ALL_CONTROLS = ("defender", "escrow", "moderator", "gate")


def run_demo_society(experiment_id: str = "society-demo",
                     logs_dir: str | None = None,
                     reputation_baseline: dict | None = None,
                     controls: set[str] | None = None) -> dict[str, Any]:
    """Run the scripted society and return the correlated cross-plane view.

    Requires range mode + diag to be active (so telemetry is emitted);
    ``logs_dir`` is where the ops spans were written (defaults to the diag dir).
    ``reputation_baseline`` seeds the run with prior standing (longitudinal
    memory across runs), so a returning offender is distrusted on sight.
    ``controls`` is the set of controls to run (default all); ablate one to
    study its effect - removing it leaves its offender uncontained, which the
    regulator's verdict then fails.
    """
    controls = controls if controls is not None else set(ALL_CONTROLS)
    logs_dir = logs_dir if logs_dir is not None else diag.DIAG_DIR
    eid = experiment_id

    def view_now():
        return crossplane.correlate(eid, logs_dir=logs_dir,
                                    reputation_baseline=reputation_baseline)

    buyer = live.LiveSession("buyer-1", session_id="S-BUYER", experiment_id=eid)
    seller2 = live.LiveSession("seller-2", session_id="S-S2", experiment_id=eid)
    attacker = live.LiveSession("attacker-1", session_id="S-ATK",
                                experiment_id=eid)
    user = live.LiveSession("user-1", session_id="S-USER", experiment_id=eid)
    troll = live.LiveSession("troll-1", session_id="S-TROLL", experiment_id=eid)

    # Economy: the buyer pays a scammer and an honest seller; one delivers.
    buyer.pay("seller-1", 50, "widget")
    buyer.pay("seller-2", 30, "gadget")
    seller2.deliver("buyer-1", "gadget")
    # Social: a normal post and an abusive one.
    user.post("general", "happy to trade fairly here", "p1")
    troll.post("general", "SCAM click here for free money now", "p2")
    # Security: the attacker fans out across services (recon), with real spans.
    services = [("market.obscura", 8001), ("forum.obscura", 8002),
                ("bank.obscura", 8003)]
    for i, (addr, port) in enumerate(services):
        attacker.observer.emit("dial.out", session_id="S-ATK", addr=addr,
                               port=port)
        _emit_circuit(f"atk-{i}", "S-ATK", f"{addr}:{port}")

    # Controls each own their domain; any can be ablated to study its effect.
    if "defender" in controls:
        live.LiveDefender("defender-1", experiment_id=eid).assess(view_now())
    if "moderator" in controls:
        live.LiveModerator("moderator", experiment_id=eid).moderate(
            load_events(eid))
    if "escrow" in controls:
        escrow = live.LiveEscrow("escrow", experiment_id=eid, grace=1)
        escrow.settle(load_events(eid))
        escrow.settle(load_events(eid))
    if "gate" in controls:
        live.LiveReputationGate("reputation-gate", experiment_id=eid,
                                threshold=0).enforce(view_now())

    # The investigator files cases; the regulator issues the verdict.
    view = view_now()
    live.LiveInvestigator("investigator", experiment_id=eid).investigate(view)
    live.LiveRegulator("regulator", experiment_id=eid).rule(view)
    return view_now()
