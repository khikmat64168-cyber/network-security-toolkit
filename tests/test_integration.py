"""
Integration tests — cross-module pipelines and CLI smoke tests (Phase 5).

Unlike the per-module unit test files, these tests exercise multiple
components together to catch integration bugs that unit tests miss
(e.g. a field name mismatch between two modules that each pass their
own unit tests in isolation).

No root privileges or live network access are required:
  - CLI tests use Click's CliRunner, which invokes commands in-process.
  - Packet pipeline tests use Scapy's packet *construction* API (no
    sockets), the same approach used throughout tests/test_sniffer.py.
  - `sniff` / `arp-watch` are tested only for their root-check guard —
    the actual capture loop opens a raw socket and is out of scope for
    an automated, sandboxed test suite.
"""
from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from src.analyzer.engine import AnalysisEngine
from src.arp_detector.events import ARPEventType
from src.arp_detector.monitor import ARPMonitor
from src.cli.main import cli
from src.core.config import AnalyzerConfig, ArpDetectorConfig, AppConfig, NetworkConfig
from src.core.logger import _reset_logging_for_testing, get_logger, setup_logging
from src.sniffer.parsers import ParserDispatcher


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestCLISmoke:
    def test_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "sniff" in result.output
        assert "arp-watch" in result.output

    def test_version_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_no_subcommand_shows_banner_and_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_status_runs_without_root(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0
        assert "Configuration" in result.output

    def test_status_reflects_config_file_overrides(self, tmp_path) -> None:
        config_file = tmp_path / "custom.yaml"
        config_file.write_text("logging:\n  level: WARNING\n")
        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(config_file), "status"])
        assert result.exit_code == 0
        assert "WARNING" in result.output

    def test_malformed_config_file_exits_cleanly(self, tmp_path) -> None:
        bad_config = tmp_path / "bad.yaml"
        bad_config.write_text("not: valid: yaml: [")
        runner = CliRunner()
        result = runner.invoke(cli, ["--config", str(bad_config), "status"])
        assert result.exit_code == 1
        assert "Configuration Error" in result.output
        # No raw Python traceback should reach the user.
        assert "Traceback" not in result.output

    def test_sniff_without_root_shows_permission_panel(self) -> None:
        runner = CliRunner()
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["sniff"])
        assert result.exit_code == 1
        assert "Permission Error" in result.output

    def test_arp_watch_without_root_shows_permission_panel(self) -> None:
        runner = CliRunner()
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["arp-watch"])
        assert result.exit_code == 1
        assert "Permission Error" in result.output

    def test_interfaces_runs_without_root(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["interfaces"])
        # Must not crash even on a CI box with zero or many interfaces.
        assert result.exit_code == 0


# ──────────────────────────────────────────────────────────────────────────────
# Sniffer → Analyzer pipeline
# ──────────────────────────────────────────────────────────────────────────────

class TestSnifferAnalyzerPipeline:
    """
    Builds real Scapy packets, runs them through ParserDispatcher (Phase 2)
    and then AnalysisEngine (Phase 3) exactly as the `sniff` command does,
    to confirm the two modules' data contracts (ParsedPacket) still match.
    """

    def _engine(self) -> AnalysisEngine:
        return AnalysisEngine(
            AnalyzerConfig(
                detect_credentials=True,
                suspicious_port_scan_threshold=5,
                alert_on_suspicious=True,
            )
        )

    def test_tcp_packet_flows_end_to_end(self) -> None:
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        parsed = ParserDispatcher.dispatch(pkt)
        engine = self._engine()
        engine.process(parsed)
        assert engine.stats.total_packets == 1

    def test_credential_payload_flows_to_alert(self) -> None:
        import base64

        creds = base64.b64encode(b"admin:secret").decode()
        payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        pkt = (
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.6")
            / TCP(sport=51000, dport=80)
            / Raw(load=payload)
        )
        parsed = ParserDispatcher.dispatch(pkt)
        engine = self._engine()
        engine.process(parsed)
        assert engine.alerts.credential_count == 1

    def test_port_scan_sequence_triggers_threat_alert(self) -> None:
        engine = self._engine()
        for port in range(1, 8):
            pkt = (
                Ether()
                / IP(src="10.0.0.9", dst="10.0.0.10")
                / TCP(sport=40000, dport=port, flags="S")
            )
            parsed = ParserDispatcher.dispatch(pkt)
            engine.process(parsed)
        assert engine.alerts.threat_count == 1

    def test_udp_packet_flows_end_to_end(self) -> None:
        pkt = Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=5353, dport=5353)
        parsed = ParserDispatcher.dispatch(pkt)
        engine = self._engine()
        engine.process(parsed)
        assert engine.stats.total_packets == 1
        breakdown = {p: cnt for p, cnt, _, _ in engine.stats.protocol_breakdown()}
        assert sum(breakdown.values()) == 1


# ──────────────────────────────────────────────────────────────────────────────
# ARP table → detector → monitor pipeline
# ──────────────────────────────────────────────────────────────────────────────

class TestARPMonitorPipeline:
    """
    Drives ARPMonitor._on_packet() directly with real Scapy ARP packets
    (constructed, not sent) to verify the full table → detector →
    event logger → alert manager chain without opening a raw socket.
    """

    def _monitor(self, gateway: str | None = None) -> ARPMonitor:
        arp_cfg = ArpDetectorConfig(gateway_ip=gateway)
        net_cfg = NetworkConfig()
        monitor = ARPMonitor(arp_cfg, net_cfg)
        # Avoid seeding from the real OS ARP cache during tests.
        with patch("src.arp_detector.table.get_system_arp_cache", return_value={}):
            monitor.table.load_from_system()
        return monitor

    def _arp_packet(self, op: int, psrc: str, hwsrc: str, pdst: str) -> Ether:
        return Ether() / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst)

    def test_non_arp_packet_is_ignored(self) -> None:
        monitor = self._monitor()
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        monitor._on_packet(pkt)
        assert monitor.packet_count == 0
        assert monitor.event_logger.total == 0

    def test_first_seen_binding_produces_no_alert(self) -> None:
        monitor = self._monitor()
        pkt = self._arp_packet(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.0.0.2")
        monitor._on_packet(pkt)
        assert monitor.packet_count == 1
        assert monitor.event_logger.total == 0
        assert monitor.table.known_mac("10.0.0.1") == "aa:bb:cc:dd:ee:01"

    def test_gateway_mac_change_triggers_critical_alert(self) -> None:
        monitor = self._monitor(gateway="10.0.0.1")
        monitor._on_packet(
            self._arp_packet(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.0.0.2")
        )
        monitor._on_packet(
            self._arp_packet(op=2, psrc="10.0.0.1", hwsrc="ff:ff:ff:ff:ff:ff", pdst="10.0.0.2")
        )
        gw_events = [
            e for e in monitor.event_logger.events
            if e.event_type == ARPEventType.GATEWAY_MAC_CHANGE
        ]
        assert len(gw_events) == 1
        assert gw_events[0].severity == "critical"
        assert monitor.alert_manager.total_alerts == 1
        assert monitor.alert_manager.critical_alerts == 1

    def test_trusted_ip_never_alerts(self) -> None:
        arp_cfg = ArpDetectorConfig(trusted_ips=["10.0.0.1"])
        monitor = ARPMonitor(arp_cfg, NetworkConfig())
        monitor._on_packet(
            self._arp_packet(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="10.0.0.2")
        )
        monitor._on_packet(
            self._arp_packet(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="10.0.0.2")
        )
        assert monitor.event_logger.total == 0
        assert monitor.alert_manager.total_alerts == 0


# ──────────────────────────────────────────────────────────────────────────────
# Config → Logging integration
# ──────────────────────────────────────────────────────────────────────────────

class TestConfigLoggingIntegration:
    def test_loaded_config_drives_logging_setup(self, tmp_path, reset_logging) -> None:
        log_file = tmp_path / "integration.log"
        config_file = tmp_path / "config.yaml"
        config_file.write_text(f"logging:\n  level: DEBUG\n  file: {log_file}\n")

        app_config = AppConfig.load(config_path=config_file)
        _reset_logging_for_testing()
        setup_logging(app_config.logging)

        logger = get_logger("test_integration")
        logger.debug("integration test message")

        assert log_file.exists()
        assert "integration test message" in log_file.read_text()
