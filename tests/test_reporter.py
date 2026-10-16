"""
Tests for Phase 10 — HTML Report Generator.

Coverage
────────
* ReportData properties       (models.py)
* TLSFinding / InterfaceInfo  (models.py)
* ReportBuilder               (builder.py)
* render()                    (renderer.py)
* write() / default_output_path (writer.py)
* report CLI smoke            (cli/main.py)
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nst.reporter.builder import ReportBuilder, _tls_severity
from nst.reporter.models import InterfaceInfo, ReportData, TLSFinding
from nst.reporter.renderer import _badge, _expiry_cell, render
from nst.reporter.writer import default_output_path, write


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _report(
    tls: list[TLSFinding] | None = None,
    ifaces: list[InterfaceInfo] | None = None,
) -> ReportData:
    return ReportData(
        generated_at=datetime(2026, 7, 17, 12, 0, 0),
        tls_findings=tls or [],
        interfaces=ifaces or [],
    )


def _finding(
    host: str = "example.com",
    severity: str = "ok",
    issues: list[str] | None = None,
    days: int | None = 90,
    port: int = 443,
) -> TLSFinding:
    return TLSFinding(
        host=host,
        port=port,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        subject="CN=example.com",
        issuer="CN=Let's Encrypt",
        days_until_expiry=days,
        issues=issues or [],
        severity=severity,
    )


def _mock_tls_result(
    host: str = "example.com",
    port: int = 443,
    error: str | None = None,
    critical: int = 0,
    high: int = 0,
    issues: list | None = None,
) -> MagicMock:
    r = MagicMock()
    r.host = host
    r.port = port
    r.tls_version = "TLSv1.3"
    r.cipher_suite = "TLS_AES_256_GCM_SHA384"
    r.subject = f"CN={host}"
    r.issuer = "CN=Let's Encrypt"
    r.error = error
    r.critical_count = critical
    r.high_count = high
    r.days_until_expiry = 90
    r.issues = issues or []
    return r


# ──────────────────────────────────────────────────────────────────────────────
# ReportData — model properties
# ──────────────────────────────────────────────────────────────────────────────

class TestReportData:
    def test_total_tls_issues_sums_all_findings(self):
        data = _report(tls=[
            _finding(issues=["a", "b"]),
            _finding(issues=["c"]),
        ])
        assert data.total_tls_issues == 3

    def test_critical_tls_count(self):
        data = _report(tls=[
            _finding(severity="critical"),
            _finding(severity="ok"),
            _finding(severity="critical"),
        ])
        assert data.critical_tls_count == 2

    def test_high_tls_count(self):
        data = _report(tls=[
            _finding(severity="high"),
            _finding(severity="ok"),
        ])
        assert data.high_tls_count == 1

    def test_ok_tls_count(self):
        data = _report(tls=[
            _finding(severity="ok"),
            _finding(severity="ok"),
            _finding(severity="warning"),
        ])
        assert data.ok_tls_count == 2

    def test_warning_tls_count(self):
        data = _report(tls=[_finding(severity="warning")])
        assert data.warning_tls_count == 1

    def test_empty_report_all_zeros(self):
        data = _report()
        assert data.total_tls_issues == 0
        assert data.critical_tls_count == 0
        assert data.ok_tls_count == 0

    def test_tls_finding_label(self):
        f = _finding(host="github.com", port=443)
        assert f.label == "github.com:443"


# ──────────────────────────────────────────────────────────────────────────────
# _tls_severity helper
# ──────────────────────────────────────────────────────────────────────────────

class TestTLSSeverityHelper:
    def test_error_result_returns_error(self):
        r = _mock_tls_result(error="Connection refused")
        assert _tls_severity(r) == "error"

    def test_critical_issues_returns_critical(self):
        r = _mock_tls_result(critical=1)
        assert _tls_severity(r) == "critical"

    def test_high_issues_returns_high(self):
        r = _mock_tls_result(high=1)
        assert _tls_severity(r) == "high"

    def test_warning_issues_returns_warning(self):
        issue = MagicMock()
        issue.issue_type.value = "expiring_soon"
        issue.detail = "Expires in 20 days"
        r = _mock_tls_result(issues=[issue])
        assert _tls_severity(r) == "warning"

    def test_clean_result_returns_ok(self):
        r = _mock_tls_result()
        assert _tls_severity(r) == "ok"


# ──────────────────────────────────────────────────────────────────────────────
# ReportBuilder
# ──────────────────────────────────────────────────────────────────────────────

class TestReportBuilder:
    def test_build_returns_report_data(self):
        data = ReportBuilder().build()
        assert isinstance(data, ReportData)

    def test_add_tls_results_populates_findings(self):
        r = _mock_tls_result(host="github.com")
        data = ReportBuilder().add_tls_results([r]).build()
        assert len(data.tls_findings) == 1
        assert data.tls_findings[0].host == "github.com"

    def test_add_tls_results_maps_severity(self):
        r = _mock_tls_result(critical=1)
        data = ReportBuilder().add_tls_results([r]).build()
        assert data.tls_findings[0].severity == "critical"

    def test_add_tls_results_error_sets_none_days(self):
        r = _mock_tls_result(error="timeout")
        data = ReportBuilder().add_tls_results([r]).build()
        assert data.tls_findings[0].days_until_expiry is None

    def test_add_tls_results_maps_issues(self):
        issue = MagicMock()
        issue.issue_type.value = "weak_cipher"
        issue.detail = "RC4 detected"
        r = _mock_tls_result(issues=[issue])
        data = ReportBuilder().add_tls_results([r]).build()
        assert "weak_cipher: RC4 detected" in data.tls_findings[0].issues

    def test_add_interfaces_skips_on_error(self):
        with patch(
            "nst.sniffer.interface.InterfaceManager.list_interfaces",
            side_effect=Exception("no scapy"),
        ):
            data = ReportBuilder().add_interfaces().build()
        assert data.interfaces == []

    def test_chaining_returns_builder(self):
        builder = ReportBuilder()
        result = builder.add_tls_results([])
        assert result is builder


# ──────────────────────────────────────────────────────────────────────────────
# Renderer
# ──────────────────────────────────────────────────────────────────────────────

class TestRenderer:
    def test_render_returns_string(self):
        html = render(_report())
        assert isinstance(html, str)

    def test_render_is_valid_html5(self):
        html = render(_report())
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_render_contains_title(self):
        html = render(_report())
        assert "NST Security Report" in html

    def test_render_includes_tls_host(self):
        html = render(_report(tls=[_finding(host="github.com")]))
        assert "github.com" in html

    def test_render_includes_interface_name(self):
        iface = InterfaceInfo(name="eth0", ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff")
        html = render(_report(ifaces=[iface]))
        assert "eth0" in html

    def test_render_escapes_html_special_chars(self):
        f = _finding(host="<script>alert(1)</script>")
        html = render(_report(tls=[f]))
        assert "<script>" not in html

    def test_badge_ok(self):
        assert "b-ok" in _badge("ok")

    def test_badge_critical(self):
        assert "b-crit" in _badge("critical")

    def test_expiry_cell_expired(self):
        cell = _expiry_cell(-5, error=False)
        assert "Expired" in cell

    def test_expiry_cell_soon(self):
        cell = _expiry_cell(10, error=False)
        assert "b-crit" in cell

    def test_expiry_cell_warning(self):
        cell = _expiry_cell(25, error=False)
        assert "b-warn" in cell

    def test_expiry_cell_healthy(self):
        cell = _expiry_cell(120, error=False)
        assert "120d" in cell

    def test_expiry_cell_error(self):
        cell = _expiry_cell(None, error=True)
        assert "N/A" in cell


# ──────────────────────────────────────────────────────────────────────────────
# Writer
# ──────────────────────────────────────────────────────────────────────────────

class TestWriter:
    def test_write_creates_file(self, tmp_path: Path):
        data = _report()
        out = write(data, tmp_path / "report.html")
        assert out.exists()
        assert out.stat().st_size > 0

    def test_write_file_contains_html(self, tmp_path: Path):
        data = _report()
        out = write(data, tmp_path / "report.html")
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_write_creates_parent_dirs(self, tmp_path: Path):
        data = _report()
        out = write(data, tmp_path / "deep" / "nested" / "report.html")
        assert out.exists()

    def test_default_output_path_has_timestamp(self):
        data = _report()
        p = default_output_path(data)
        assert "nst_report_" in p.name
        assert p.suffix == ".html"

    def test_write_does_not_open_browser_by_default(self, tmp_path: Path):
        data = _report()
        with patch("webbrowser.open") as mock_open:
            write(data, tmp_path / "r.html", open_browser=False)
        mock_open.assert_not_called()

    def test_write_opens_browser_when_requested(self, tmp_path: Path):
        data = _report()
        with patch("webbrowser.open") as mock_open:
            write(data, tmp_path / "r.html", open_browser=True)
        mock_open.assert_called_once()


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestReportCLI:
    def test_report_no_args_generates_file(self, tmp_path: Path):
        from nst.cli.main import cli

        out = tmp_path / "report.html"
        with patch("nst.sniffer.interface.InterfaceManager.list_interfaces", return_value=[]), \
             patch("nst.sniffer.interface.InterfaceManager.get_default", return_value=""):
            runner = CliRunner()
            result = runner.invoke(cli, ["report", "--output", str(out)])

        assert result.exit_code == 0
        assert out.exists()

    def test_report_with_tls_scans_hosts(self, tmp_path: Path):
        from nst.cli.main import cli

        mock_result = _mock_tls_result(host="example.com")

        out = tmp_path / "report.html"
        with patch("nst.tls_inspector.scanner.scan", return_value=mock_result), \
             patch("nst.tls_inspector.display.print_result"), \
             patch("nst.sniffer.interface.InterfaceManager.list_interfaces", return_value=[]), \
             patch("nst.sniffer.interface.InterfaceManager.get_default", return_value=""):
            runner = CliRunner()
            result = runner.invoke(
                cli, ["report", "--tls", "example.com", "--output", str(out)]
            )

        assert result.exit_code == 0
        assert out.exists()

    def test_tls_scan_save_report_creates_file(self, tmp_path: Path):
        from nst.cli.main import cli

        mock_result = _mock_tls_result(host="example.com")
        out = tmp_path / "tls_report.html"

        with patch("nst.tls_inspector.scanner.scan", return_value=mock_result), \
             patch("nst.tls_inspector.display.print_result"), \
             patch("nst.tls_inspector.display.print_summary"), \
             patch("nst.sniffer.interface.InterfaceManager.list_interfaces", return_value=[]), \
             patch("nst.sniffer.interface.InterfaceManager.get_default", return_value=""):
            runner = CliRunner()
            result = runner.invoke(
                cli,
                ["tls-scan", "example.com", "--save-report", str(out)],
            )

        assert out.exists()
