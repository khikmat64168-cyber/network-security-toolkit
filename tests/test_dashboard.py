"""
Unit tests for the Network Traffic Dashboard (Phase 6).

All tests run without root privileges or live network access:
  - DashboardStats tests use hand-crafted ParsedPacket objects.
  - Renderer tests call render() directly on a DashboardSnapshot.
  - CLI smoke tests use Click's CliRunner with a patched os.geteuid.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

from click.testing import CliRunner

from src.cli.main import cli
from src.dashboard.renderer import _fmt_bytes, render
from src.dashboard.stats import DashboardSnapshot, DashboardStats
from src.sniffer.parsers.base import ParsedPacket, Protocol


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _pkt(
    protocol: Protocol = Protocol.TCP,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int | None = 1234,
    dst_port: int | None = 80,
    length: int = 64,
    summary: str = "SYN",
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        summary=summary,
    )


def _snapshot(**kwargs: object) -> DashboardSnapshot:
    defaults: dict = dict(
        elapsed=5.0,
        total_packets=10,
        total_bytes=640,
        pps=2.0,
        protocol_counts={"TCP": 7, "UDP": 3},
        top_sources=[("10.0.0.1", 6), ("10.0.0.2", 4)],
        top_destinations=[("10.0.0.2", 8), ("10.0.0.1", 2)],
        alert_count=0,
        recent=[],
    )
    defaults.update(kwargs)
    return DashboardSnapshot(**defaults)  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# DashboardStats
# ──────────────────────────────────────────────────────────────────────────────

class TestDashboardStats:
    def test_starts_empty(self) -> None:
        stats = DashboardStats()
        snap = stats.get_snapshot()
        assert snap.total_packets == 0
        assert snap.total_bytes == 0
        assert snap.alert_count == 0
        assert snap.recent == []

    def test_record_packet_increments_total(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt(length=100))
        snap = stats.get_snapshot()
        assert snap.total_packets == 1
        assert snap.total_bytes == 100

    def test_record_multiple_packets(self) -> None:
        stats = DashboardStats()
        for _ in range(5):
            stats.record_packet(_pkt(length=50))
        snap = stats.get_snapshot()
        assert snap.total_packets == 5
        assert snap.total_bytes == 250

    def test_protocol_counter_tracks_correctly(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt(protocol=Protocol.TCP))
        stats.record_packet(_pkt(protocol=Protocol.TCP))
        stats.record_packet(_pkt(protocol=Protocol.UDP))
        snap = stats.get_snapshot()
        assert snap.protocol_counts["TCP"] == 2
        assert snap.protocol_counts["UDP"] == 1

    def test_top_sources_populated(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt(src_ip="1.1.1.1"))
        stats.record_packet(_pkt(src_ip="1.1.1.1"))
        stats.record_packet(_pkt(src_ip="2.2.2.2"))
        snap = stats.get_snapshot()
        sources = dict(snap.top_sources)
        assert sources["1.1.1.1"] == 2
        assert sources["2.2.2.2"] == 1

    def test_record_alert_increments_count(self) -> None:
        stats = DashboardStats()
        stats.record_alert()
        stats.record_alert()
        assert stats.get_snapshot().alert_count == 2

    def test_recent_ring_buffer_holds_packets(self) -> None:
        stats = DashboardStats()
        for i in range(5):
            stats.record_packet(_pkt(src_ip=f"10.0.0.{i}"))
        snap = stats.get_snapshot()
        assert len(snap.recent) == 5

    def test_pps_is_positive_after_one_packet(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt())
        snap = stats.get_snapshot()
        assert snap.pps > 0

    def test_packet_row_src_includes_port(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt(src_ip="10.0.0.1", src_port=1234))
        snap = stats.get_snapshot()
        assert "1234" in snap.recent[0].src

    def test_packet_row_without_port_shows_ip_only(self) -> None:
        stats = DashboardStats()
        stats.record_packet(_pkt(src_ip="10.0.0.1", src_port=None, dst_port=None))
        snap = stats.get_snapshot()
        assert snap.recent[0].src == "10.0.0.1"


# ──────────────────────────────────────────────────────────────────────────────
# Renderer
# ──────────────────────────────────────────────────────────────────────────────

class TestRenderer:
    def test_render_returns_layout(self) -> None:
        from rich.layout import Layout

        result = render(_snapshot())
        assert isinstance(result, Layout)

    def test_render_has_named_sections(self) -> None:
        layout = render(_snapshot())
        names = {child.name for child in layout.children}
        assert "header" in names
        assert "body" in names
        assert "footer" in names

    def test_render_does_not_raise_with_empty_snapshot(self) -> None:
        snap = _snapshot(
            total_packets=0,
            total_bytes=0,
            protocol_counts={},
            top_sources=[],
            top_destinations=[],
            recent=[],
        )
        render(snap)  # must not raise

    def test_render_does_not_raise_with_alerts(self) -> None:
        render(_snapshot(alert_count=5))  # must not raise

    def test_fmt_bytes_under_1kb(self) -> None:
        assert _fmt_bytes(512) == "512.0 B"

    def test_fmt_bytes_kilobytes(self) -> None:
        assert "KB" in _fmt_bytes(2048)

    def test_fmt_bytes_megabytes(self) -> None:
        assert "MB" in _fmt_bytes(2 * 1024 * 1024)


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDashboardCLI:
    def test_dashboard_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output.lower()

    def test_dashboard_without_root_shows_permission_panel(self) -> None:
        runner = CliRunner()
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["dashboard"])
        assert result.exit_code == 1
        assert "Permission Error" in result.output

    def test_dashboard_appears_in_top_level_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "dashboard" in result.output
