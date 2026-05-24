"""Unit tests for the shared connection-diagnostic helper."""

from src.utils import diagnose as diag_mod
from src.utils.diagnose import (
    DiagnosticReport,
    DiagnosticStep,
    format_report_text,
    run_diagnostics,
)
from src.core import internet_discovery as net_mod


class _FakeError(net_mod.RegistryHTTPError):
    """Convenience for emitting registry errors with a chosen kind."""


def test_report_ok_aggregates_steps():
    rep = DiagnosticReport(registry_url="https://x", address=None, steps=[
        DiagnosticStep("a", True, "ok"),
        DiagnosticStep("b", True, "ok"),
    ])
    assert rep.ok is True
    assert rep.first_failure is None


def test_report_first_failure_reports_in_order():
    rep = DiagnosticReport(registry_url="https://x", address=None, steps=[
        DiagnosticStep("a", True, "ok"),
        DiagnosticStep("b", False, "boom"),
        DiagnosticStep("c", False, "later boom"),
    ])
    assert rep.ok is False
    assert rep.first_failure.name == "b"


def test_format_report_text_includes_detail_and_summary_lines():
    rep = DiagnosticReport(registry_url="https://x", address="a.obscura", steps=[
        DiagnosticStep("Registry health", True, "ok"),
        DiagnosticStep("Live peers", False, "nodes=0 exits=0",
                       detail="No peers heartbeating."),
    ])
    out = format_report_text(rep)
    assert "Registry health" in out
    assert "Live peers" in out
    assert "No peers" in out
    assert "First failure: Live peers" in out


def test_run_diagnostics_short_circuits_when_registry_unreachable(monkeypatch):
    def boom(*_a, **_kw):
        raise _FakeError("transport", "DNS failure")
    monkeypatch.setattr(net_mod, "registry_request_json", boom)
    monkeypatch.setattr(diag_mod, "run_diagnostics", run_diagnostics, raising=False)

    report = run_diagnostics(None)
    assert report.ok is False
    assert len(report.steps) == 1
    assert report.steps[0].name == "Registry health"


def test_run_diagnostics_flags_html_fallback_as_missing_endpoint(monkeypatch):
    """When /hs/descriptor returns text/html (Cloudflare/nginx SPA fallback),
    the diagnostic should explicitly tell the user the registry needs a
    redeploy rather than producing a vague 'descriptor failed' message.
    """
    state = {"calls": 0}

    def fake_request(url, **_kw):
        state["calls"] += 1
        if url.endswith("/health"):
            return {"peers": 0, "breakdown": {}}
        # Descriptor endpoint returns HTML - simulate the deployed-registry-
        # missing-/hs-routes scenario.
        raise _FakeError(
            "content_type",
            "non-JSON",
            status=200,
            content_type="text/html",
            body_preview="<!doctype html>",
        )

    monkeypatch.setattr(net_mod, "registry_request_json", fake_request)
    monkeypatch.setattr(net_mod, "fetch_peers_from_registry", lambda *_a, **_kw: [])

    report = run_diagnostics("aaaaaaaaaaaaaaaa.obscura")
    assert report.ok is False
    descriptor_step = next(s for s in report.steps if s.name == "Descriptor endpoint")
    assert "non-JSON" in descriptor_step.summary
    assert "redeployed" in (descriptor_step.detail or "")


def test_run_diagnostics_rejects_malformed_address(monkeypatch):
    monkeypatch.setattr(
        net_mod, "registry_request_json", lambda *_a, **_kw: {"peers": 0, "breakdown": {}},
    )
    monkeypatch.setattr(net_mod, "fetch_peers_from_registry", lambda *_a, **_kw: [])

    report = run_diagnostics("not-an-obscura-addr")
    assert report.ok is False
    assert any(s.name == "Address shape" for s in report.steps)
