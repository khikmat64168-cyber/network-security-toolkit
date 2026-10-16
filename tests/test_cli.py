"""
CLI command tests for the Network Security Toolkit.

Every capture subcommand is exercised end-to-end through Click's
CliRunner with the capture layer replaced by a fake that replays real
Scapy packets — no root privileges or network access required.

Tests cover:
  - Global options (--config validation, --debug)
  - status output for every config section
  - sniff / dashboard packet pipelines and their error panels
  - arp-watch / dns-watch / mac-watch error handling
  - report, geoip and interfaces commands
  - main() last-line-of-defence exception handling
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, List
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from nst.cli.main import cli, main
from nst.core.exceptions import (
    CaptureError,
    InsufficientPermissionsError,
    InterfaceError,
    NetworkToolkitError,
)
from nst.sniffer.interface import NetworkInterface


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

class _FakeCapture:
    """Stands in for PacketCapture: replays *packets*, then simulates Ctrl-C."""

    def __init__(self, packets: List[Any], error: Exception | None = None) -> None:
        self._packets = packets
        self._error = error
        self.packet_count = 0

    def __call__(self, *_args: object) -> "_FakeCapture":
        return self

    def start(self, on_packet: Callable[[Any], None]) -> None:
        if self._error is not None:
            raise self._error
        for pkt in self._packets:
            self.packet_count += 1
            on_packet(pkt)
        raise KeyboardInterrupt


def _http_basic_auth_packet() -> Any:
    payload = (
        b"GET / HTTP/1.1\r\nHost: example.com\r\n"
        b"Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n"
    )
    return (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.9")
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(load=payload)
    )


def _run_as_root(args: List[str], capture: _FakeCapture) -> Any:
    runner = CliRunner()
    with patch("os.geteuid", return_value=0), \
         patch("nst.sniffer.interface.InterfaceManager.resolve", return_value="lo0"), \
         patch("nst.sniffer.capture.PacketCapture", capture):
        return runner.invoke(cli, args)


# ──────────────────────────────────────────────────────────────────────────────
# Global options
# ──────────────────────────────────────────────────────────────────────────────

class TestGlobalOptions:
    def test_missing_config_file_is_rejected(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(cli, ["--config", str(tmp_path / "nope.yaml"), "status"])
        assert result.exit_code == 2
        assert "does not exist" in result.output

    def test_version_matches_package(self) -> None:
        from nst import __version__

        result = CliRunner().invoke(cli, ["--version"])
        assert __version__ in result.output

    def test_debug_flag_sets_console_level(self, reset_logging: None) -> None:
        import nst.core.logger as logger_module

        logger_module._reset_logging_for_testing()
        logger_module.setup_logging()   # simulate the import-time bootstrap
        CliRunner().invoke(cli, ["--debug", "status"])

        levels = [h.level for h in logging.getLogger().handlers
                  if type(h).__name__ == "RichHandler"]
        assert levels == [logging.DEBUG]


# ──────────────────────────────────────────────────────────────────────────────
# status
# ──────────────────────────────────────────────────────────────────────────────

class TestStatus:
    def test_lists_every_config_section(self) -> None:
        result = CliRunner().invoke(cli, ["status"])
        assert result.exit_code == 0
        for section in ("network", "sniffer", "analyzer", "arp_detector",
                        "dns_detector", "mac_detector", "logging"):
            assert section in result.output

    def test_shows_resolved_log_path(self, tmp_path: Path) -> None:
        log_file = tmp_path / "custom.log"
        cfg = tmp_path / "c.yaml"
        cfg.write_text(f"logging:\n  file: {log_file}\n")
        result = CliRunner().invoke(cli, ["--config", str(cfg), "status"])
        # Long paths wrap inside the table cell — compare without layout.
        flat = "".join(ch for ch in result.output if not ch.isspace() and ch != "│")
        assert "custom.log" in flat


# ──────────────────────────────────────────────────────────────────────────────
# sniff
# ──────────────────────────────────────────────────────────────────────────────

class TestSniff:
    def test_prints_packets_and_summary(self) -> None:
        result = _run_as_root(["sniff", "-c", "1"], _FakeCapture([_http_basic_auth_packet()]))
        assert result.exit_code == 0
        assert "10.0.0.5:40000" in result.output
        assert "Session Summary" in result.output
        assert "Protocol Breakdown" in result.output
        assert "Top Source IPs" in result.output

    def test_verbose_mode(self) -> None:
        result = _run_as_root(["sniff", "-v"], _FakeCapture([_http_basic_auth_packet()]))
        assert result.exit_code == 0

    def test_empty_capture_reports_no_packets(self) -> None:
        result = _run_as_root(["sniff"], _FakeCapture([]))
        assert result.exit_code == 0
        assert "No packets analysed" in result.output

    def test_permission_error_panel(self) -> None:
        capture = _FakeCapture([], error=InsufficientPermissionsError("raw socket denied"))
        result = _run_as_root(["sniff"], capture)
        assert result.exit_code == 1
        assert "Permission Error" in result.output

    def test_capture_error(self) -> None:
        result = _run_as_root(["sniff"], _FakeCapture([], error=CaptureError("boom")))
        assert result.exit_code == 1
        assert "Capture failed" in result.output

    def test_interface_error(self) -> None:
        runner = CliRunner()
        with patch("os.geteuid", return_value=0), \
             patch("nst.sniffer.interface.InterfaceManager.resolve",
                   side_effect=InterfaceError("no such iface")):
            result = runner.invoke(cli, ["sniff", "-i", "bogus0"])
        assert result.exit_code == 1
        assert "Interface error" in result.output


# ──────────────────────────────────────────────────────────────────────────────
# dashboard
# ──────────────────────────────────────────────────────────────────────────────

class TestDashboard:
    def test_records_packets_and_alerts(self) -> None:
        display = MagicMock()
        display.__enter__.return_value = display
        with patch("nst.dashboard.display.DashboardDisplay", return_value=display):
            result = _run_as_root(["dashboard"], _FakeCapture([_http_basic_auth_packet()]))
        assert result.exit_code == 0
        display.record.assert_called_once()
        display.record_alert.assert_called()

    def test_permission_error_panel(self) -> None:
        display = MagicMock()
        display.__enter__.return_value = display
        capture = _FakeCapture([], error=InsufficientPermissionsError("denied"))
        with patch("nst.dashboard.display.DashboardDisplay", return_value=display):
            result = _run_as_root(["dashboard"], capture)
        assert result.exit_code == 1
        assert "Permission Error" in result.output


# ──────────────────────────────────────────────────────────────────────────────
# *-watch monitors
# ──────────────────────────────────────────────────────────────────────────────

class TestWatchCommands:
    @pytest.mark.parametrize("command, monitor_path", [
        ("arp-watch", "nst.arp_detector.monitor.ARPMonitor"),
        ("dns-watch", "nst.dns_detector.monitor.DNSMonitor"),
        ("mac-watch", "nst.mac_detector.monitor.MACMonitor"),
    ])
    def test_permission_error_panel(self, command: str, monitor_path: str) -> None:
        monitor = MagicMock()
        monitor.start.side_effect = InsufficientPermissionsError("denied")
        monitor.table.all_entries.return_value = []
        monitor.event_logger.high_priority_events.return_value = []
        monitor.event_logger.count_by_type.return_value = 0
        with patch("os.geteuid", return_value=0), patch(monitor_path, return_value=monitor):
            result = CliRunner().invoke(cli, [command])
        assert result.exit_code == 1
        assert "Permission Error" in result.output
        assert f"sudo nst {command}" in result.output

    @pytest.mark.parametrize("command, monitor_path", [
        ("arp-watch", "nst.arp_detector.monitor.ARPMonitor"),
        ("dns-watch", "nst.dns_detector.monitor.DNSMonitor"),
        ("mac-watch", "nst.mac_detector.monitor.MACMonitor"),
    ])
    def test_capture_error(self, command: str, monitor_path: str) -> None:
        monitor = MagicMock()
        monitor.start.side_effect = CaptureError("iface down")
        monitor.table.all_entries.return_value = []
        monitor.event_logger.high_priority_events.return_value = []
        monitor.event_logger.count_by_type.return_value = 0
        with patch("os.geteuid", return_value=0), patch(monitor_path, return_value=monitor):
            result = CliRunner().invoke(cli, [command])
        assert result.exit_code == 1
        assert "capture failed" in result.output

    def test_mac_watch_summary_lists_top_macs(self) -> None:
        entry = MagicMock(mac="aa:bb:cc:dd:ee:ff", packet_count=7)
        monitor = MagicMock()
        monitor.start.side_effect = KeyboardInterrupt
        monitor.packet_count = 7
        monitor.table.total.return_value = 1
        monitor.table.all_entries.return_value = [entry]
        monitor.event_logger.count_by_type.return_value = 0
        monitor.alert_manager.total_alerts = 0
        monitor.alert_manager.critical_alerts = 0
        with patch("os.geteuid", return_value=0), \
             patch("nst.mac_detector.monitor.MACMonitor", return_value=monitor):
            result = CliRunner().invoke(cli, ["mac-watch", "--window", "2"])
        assert result.exit_code == 0
        assert "aa:bb:cc:dd:ee:ff" in result.output

    def test_dns_watch_summary_lists_resolutions(self) -> None:
        entry = MagicMock(domain="example.com", current_ip="93.184.216.34",
                          ips_seen={"93.184.216.34", "6.6.6.6"}, packet_count=3)
        monitor = MagicMock()
        monitor.start.side_effect = KeyboardInterrupt
        monitor.packet_count = 3
        monitor.table.all_entries.return_value = [entry]
        monitor.event_logger.total = 0
        monitor.event_logger.high_priority_events.return_value = []
        monitor.alert_manager.total_alerts = 0
        with patch("os.geteuid", return_value=0), \
             patch("nst.dns_detector.monitor.DNSMonitor", return_value=monitor):
            result = CliRunner().invoke(
                cli, ["dns-watch", "--trusted-domain", "cdn.example", "--no-query-tracking"]
            )
        assert result.exit_code == 0
        assert "example.com" in result.output


# ──────────────────────────────────────────────────────────────────────────────
# report / geoip / interfaces
# ──────────────────────────────────────────────────────────────────────────────

class TestReport:
    def test_writes_report_without_tls(self, tmp_path: Path) -> None:
        out = tmp_path / "r.html"
        with patch("nst.reporter.builder.ReportBuilder.add_interfaces",
                   lambda self: self):
            result = CliRunner().invoke(cli, ["report", "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "Report Generated" in result.output

    def test_tls_scan_save_report(self, tmp_path: Path) -> None:
        from tests.test_tls_inspector import _result

        out = tmp_path / "tls.html"
        with patch("nst.tls_inspector.scanner.scan", return_value=_result()), \
             patch("nst.reporter.builder.ReportBuilder.add_interfaces",
                   lambda self: self):
            result = CliRunner().invoke(
                cli, ["tls-scan", "--save-report", str(out), "example.com"]
            )
        assert result.exit_code == 0
        assert out.exists()


class TestGeoIP:
    def test_no_targets_exits_one(self) -> None:
        result = CliRunner().invoke(cli, ["geoip"])
        assert result.exit_code == 1

    def test_private_ip_needs_no_network(self) -> None:
        result = CliRunner().invoke(cli, ["geoip", "192.168.1.1"])
        assert result.exit_code == 0
        assert "192.168.1.1" in result.output


class TestInterfaces:
    def test_lists_interfaces_and_marks_default(self) -> None:
        ifaces = [
            NetworkInterface(name="en0", ip="10.0.0.2", mac="aa:aa:aa:aa:aa:aa",
                             description="Wi-Fi"),
            NetworkInterface(name="lo0", ip="127.0.0.1", mac="", description="lo0"),
        ]
        with patch("nst.sniffer.interface.InterfaceManager.list_interfaces",
                   return_value=ifaces), \
             patch("nst.sniffer.interface.InterfaceManager.get_default",
                   return_value="en0"):
            result = CliRunner().invoke(cli, ["interfaces"])
        assert result.exit_code == 0
        assert "Default capture interface" in result.output
        assert "Wi-Fi" in result.output

    def test_empty_list(self) -> None:
        with patch("nst.sniffer.interface.InterfaceManager.list_interfaces",
                   return_value=[]), \
             patch("nst.sniffer.interface.InterfaceManager.get_default",
                   side_effect=InterfaceError("none")):
            result = CliRunner().invoke(cli, ["interfaces"])
        assert result.exit_code == 0
        assert "No network interfaces found" in result.output

    def test_discovery_error(self) -> None:
        with patch("nst.sniffer.interface.InterfaceManager.list_interfaces",
                   side_effect=InterfaceError("scapy failed")):
            result = CliRunner().invoke(cli, ["interfaces"])
        assert result.exit_code == 1


# ──────────────────────────────────────────────────────────────────────────────
# main()
# ──────────────────────────────────────────────────────────────────────────────

class TestMainEntryPoint:
    @pytest.mark.parametrize("raised, code", [
        (NetworkToolkitError("bad"), 1),
        (KeyboardInterrupt(), 130),
        (RuntimeError("unexpected"), 1),
    ])
    def test_exceptions_become_exit_codes(
        self, raised: BaseException, code: int, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("nst.cli.main.cli", side_effect=raised):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == code
        assert "Traceback" not in capsys.readouterr().err
