"""
Unit tests for the DNS Spoofing Detector (Phase 7).

All tests run without root privileges or live network access:
  - DNSTable and EventLogger tests use plain Python objects.
  - DNSSpoofingDetector tests use real Scapy DNS packet construction
    (no raw sockets — Scapy's packet API works without privileges).
  - DNSMonitor._on_packet tests drive the monitor directly with
    constructed packets, like the ARP monitor tests do.
  - CLI smoke tests use Click's CliRunner with a patched os.geteuid.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from src.cli.main import cli
from src.core.config import DNSDetectorConfig, NetworkConfig
from src.dns_detector.alerts import DNSAlertManager
from src.dns_detector.detector import DNSSpoofingDetector, _extract_a_records
from src.dns_detector.events import DNSEvent, DNSEventType, EventLogger
from src.dns_detector.monitor import DNSMonitor
from src.dns_detector.table import DNSTable


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _response(
    domain: str,
    ip: str,
    dns_id: int = 1,
    ttl: int = 300,
    client_ip: str = "10.0.0.1",
    server_ip: str = "8.8.8.8",
) -> Ether:
    """Construct a DNS A-record response packet."""
    return (
        Ether()
        / IP(src=server_ip, dst=client_ip)
        / UDP(sport=53, dport=1234)
        / DNS(
            qr=1,
            id=dns_id,
            ancount=1,
            an=DNSRR(rrname=domain + ".", rdata=ip, ttl=ttl, type=1),
        )
    )


def _query(
    domain: str,
    dns_id: int = 1,
    client_ip: str = "10.0.0.1",
    server_ip: str = "8.8.8.8",
) -> Ether:
    """Construct a DNS query packet."""
    return (
        Ether()
        / IP(src=client_ip, dst=server_ip)
        / UDP(sport=1234, dport=53)
        / DNS(qr=0, id=dns_id, qd=DNSQR(qname=domain))
    )


def _event(
    event_type: DNSEventType = DNSEventType.IP_CHANGE,
    domain: str = "example.com",
    new_ip: str = "1.2.3.4",
    src_ip: str = "8.8.8.8",
    severity: str = "high",
    description: str = "test",
) -> DNSEvent:
    return DNSEvent(
        event_type=event_type,
        domain=domain,
        new_ip=new_ip,
        src_ip=src_ip,
        timestamp=datetime.now(),
        severity=severity,
        description=description,
    )


def _detector(
    trusted: list | None = None,
    track_queries: bool = False,
) -> DNSSpoofingDetector:
    return DNSSpoofingDetector(
        table=DNSTable(trusted_domains=trusted),
        track_queries=track_queries,
    )


def _monitor(
    trusted: list | None = None,
    track_queries: bool = False,
) -> DNSMonitor:
    cfg = DNSDetectorConfig(
        trusted_domains=trusted or [],
        track_queries=track_queries,
    )
    return DNSMonitor(cfg, NetworkConfig())


# ──────────────────────────────────────────────────────────────────────────────
# DNSTable
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSTable:
    def test_new_domain_returns_none(self) -> None:
        table = DNSTable()
        assert table.update("example.com", "1.2.3.4") is None

    def test_same_ip_returns_none(self) -> None:
        table = DNSTable()
        table.update("example.com", "1.2.3.4")
        assert table.update("example.com", "1.2.3.4") is None

    def test_ip_change_returns_old_ip(self) -> None:
        table = DNSTable()
        table.update("example.com", "1.2.3.4")
        old = table.update("example.com", "5.6.7.8")
        assert old == "1.2.3.4"

    def test_known_ip_returns_current(self) -> None:
        table = DNSTable()
        table.update("example.com", "1.2.3.4")
        assert table.known_ip("example.com") == "1.2.3.4"

    def test_known_ip_unknown_domain_returns_none(self) -> None:
        assert DNSTable().known_ip("unknown.com") is None

    def test_known_ips_tracks_all_seen(self) -> None:
        table = DNSTable()
        table.update("example.com", "1.1.1.1")
        table.update("example.com", "2.2.2.2")
        assert table.known_ips("example.com") == {"1.1.1.1", "2.2.2.2"}

    def test_ip_count_reflects_unique_ips(self) -> None:
        table = DNSTable()
        table.update("example.com", "1.1.1.1")
        table.update("example.com", "2.2.2.2")
        table.update("example.com", "1.1.1.1")
        assert table.ip_count("example.com") == 2

    def test_trusted_domain_never_returns_old_ip(self) -> None:
        table = DNSTable(trusted_domains=["cdn.example.com"])
        table.update("cdn.example.com", "1.1.1.1")
        old = table.update("cdn.example.com", "2.2.2.2")
        assert old is None

    def test_all_entries_sorted_by_domain(self) -> None:
        table = DNSTable()
        table.update("z.example.com", "1.1.1.1")
        table.update("a.example.com", "2.2.2.2")
        domains = [e.domain for e in table.all_entries()]
        assert domains == sorted(domains)


# ──────────────────────────────────────────────────────────────────────────────
# DNSEvent + EventLogger
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSEvent:
    def test_severity_level_maps_correctly(self) -> None:
        assert _event(severity="low").severity_level() == 0
        assert _event(severity="medium").severity_level() == 1
        assert _event(severity="high").severity_level() == 2
        assert _event(severity="critical").severity_level() == 3

    def test_unknown_severity_returns_zero(self) -> None:
        assert _event(severity="bogus").severity_level() == 0


class TestEventLogger:
    def test_starts_empty(self) -> None:
        log = EventLogger()
        assert log.total == 0
        assert log.events == []

    def test_log_appends_event(self) -> None:
        log = EventLogger()
        log.log(_event())
        assert log.total == 1

    def test_count_by_type(self) -> None:
        log = EventLogger()
        log.log(_event(event_type=DNSEventType.IP_CHANGE))
        log.log(_event(event_type=DNSEventType.IP_CHANGE))
        log.log(_event(event_type=DNSEventType.UNSOLICITED))
        assert log.count_by_type(DNSEventType.IP_CHANGE) == 2
        assert log.count_by_type(DNSEventType.UNSOLICITED) == 1

    def test_high_priority_events_filters_correctly(self) -> None:
        log = EventLogger()
        log.log(_event(severity="medium"))
        log.log(_event(severity="high"))
        log.log(_event(severity="critical"))
        hp = log.high_priority_events()
        assert len(hp) == 2
        assert all(e.severity in ("high", "critical") for e in hp)

    def test_events_returns_snapshot(self) -> None:
        log = EventLogger()
        snapshot = log.events
        log.log(_event())
        assert len(snapshot) == 0


# ──────────────────────────────────────────────────────────────────────────────
# _extract_a_records
# ──────────────────────────────────────────────────────────────────────────────

class TestExtractARecords:
    def test_extracts_single_a_record(self) -> None:
        pkt = _response("example.com", "1.2.3.4", ttl=300)
        records = _extract_a_records(pkt[DNS])
        assert len(records) == 1
        domain, ip, ttl = records[0]
        assert domain == "example.com"
        assert ip == "1.2.3.4"
        assert ttl == 300

    def test_returns_empty_for_query(self) -> None:
        pkt = _query("example.com")
        assert _extract_a_records(pkt[DNS]) == []

    def test_extracts_multiple_a_records(self) -> None:
        dns_pkt = DNS(
            qr=1,
            ancount=2,
            an=[
                DNSRR(rrname="example.com.", rdata="1.1.1.1", ttl=60, type=1),
                DNSRR(rrname="example.com.", rdata="2.2.2.2", ttl=60, type=1),
            ],
        )
        records = _extract_a_records(dns_pkt)
        assert len(records) == 2
        ips = {r[1] for r in records}
        assert ips == {"1.1.1.1", "2.2.2.2"}


# ──────────────────────────────────────────────────────────────────────────────
# DNSSpoofingDetector
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSSpoofingDetector:
    def test_query_packet_returns_no_events(self) -> None:
        det = _detector()
        pkt = _query("example.com")
        events = det.analyze(pkt[DNS], src_ip="10.0.0.1", dst_ip="8.8.8.8")
        assert events == []

    def test_new_domain_response_no_events(self) -> None:
        det = _detector()
        pkt = _response("example.com", "1.2.3.4")
        events = det.analyze(pkt[DNS], src_ip="8.8.8.8", dst_ip="10.0.0.1")
        assert events == []

    def test_ip_change_raises_high_event(self) -> None:
        det = _detector()
        pkt1 = _response("example.com", "1.2.3.4")
        det.analyze(pkt1[DNS], "8.8.8.8", "10.0.0.1")
        pkt2 = _response("example.com", "9.9.9.9")
        events = det.analyze(pkt2[DNS], "8.8.8.8", "10.0.0.1")
        ip_change = [e for e in events if e.event_type == DNSEventType.IP_CHANGE]
        assert len(ip_change) == 1
        assert ip_change[0].severity == "high"
        assert ip_change[0].old_ip == "1.2.3.4"
        assert ip_change[0].new_ip == "9.9.9.9"

    def test_same_ip_response_no_events(self) -> None:
        det = _detector()
        pkt = _response("example.com", "1.2.3.4")
        det.analyze(pkt[DNS], "8.8.8.8", "10.0.0.1")
        events = det.analyze(pkt[DNS], "8.8.8.8", "10.0.0.1")
        assert events == []

    def test_zero_ttl_raises_medium_event(self) -> None:
        det = _detector()
        pkt = _response("example.com", "1.2.3.4", ttl=0)
        events = det.analyze(pkt[DNS], "8.8.8.8", "10.0.0.1")
        zero_ttl = [e for e in events if e.event_type == DNSEventType.ZERO_TTL]
        assert len(zero_ttl) == 1
        assert zero_ttl[0].severity == "medium"
        assert zero_ttl[0].ttl == 0

    def test_multiple_ips_raises_high_event(self) -> None:
        det = _detector()
        det.analyze(_response("example.com", "1.1.1.1")[DNS], "8.8.8.8", "10.0.0.1")
        events = det.analyze(
            _response("example.com", "2.2.2.2")[DNS], "8.8.8.8", "10.0.0.1"
        )
        multi = [e for e in events if e.event_type == DNSEventType.MULTIPLE_IPS]
        assert len(multi) == 1
        assert multi[0].severity == "high"

    def test_multiple_ips_fires_only_once(self) -> None:
        det = _detector()
        all_multi = []
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            evts = det.analyze(
                _response("example.com", ip)[DNS], "8.8.8.8", "10.0.0.1"
            )
            all_multi.extend(
                e for e in evts if e.event_type == DNSEventType.MULTIPLE_IPS
            )
        assert len(all_multi) == 1

    def test_unsolicited_response_detected(self) -> None:
        det = DNSSpoofingDetector(table=DNSTable(), track_queries=True)
        pkt = _response("example.com", "1.2.3.4", dns_id=9999)
        events = det.analyze(pkt[DNS], src_ip="8.8.8.8", dst_ip="10.0.0.1")
        unsolicit = [e for e in events if e.event_type == DNSEventType.UNSOLICITED]
        assert len(unsolicit) == 1
        assert unsolicit[0].severity == "medium"

    def test_solicited_response_no_unsolicited_event(self) -> None:
        det = DNSSpoofingDetector(table=DNSTable(), track_queries=True)
        q = _query("example.com", dns_id=42)
        det.analyze(q[DNS], src_ip="10.0.0.1", dst_ip="8.8.8.8")
        r = _response("example.com", "1.2.3.4", dns_id=42)
        events = det.analyze(r[DNS], src_ip="8.8.8.8", dst_ip="10.0.0.1")
        unsolicit = [e for e in events if e.event_type == DNSEventType.UNSOLICITED]
        assert len(unsolicit) == 0

    def test_trusted_domain_produces_no_events(self) -> None:
        det = DNSSpoofingDetector(
            table=DNSTable(trusted_domains=["cdn.example.com"]),
            track_queries=False,
        )
        det.analyze(
            _response("cdn.example.com", "1.1.1.1")[DNS], "8.8.8.8", "10.0.0.1"
        )
        events = det.analyze(
            _response("cdn.example.com", "2.2.2.2")[DNS], "8.8.8.8", "10.0.0.1"
        )
        assert events == []


# ──────────────────────────────────────────────────────────────────────────────
# DNSMonitor._on_packet
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSMonitorOnPacket:
    def test_non_dns_packet_is_ignored(self) -> None:
        from scapy.layers.inet import TCP
        monitor = _monitor()
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        monitor._on_packet(pkt)
        assert monitor.packet_count == 0

    def test_first_response_no_alert(self) -> None:
        monitor = _monitor()
        monitor._on_packet(_response("example.com", "1.2.3.4"))
        assert monitor.packet_count == 1
        assert monitor.event_logger.total == 0

    def test_ip_change_triggers_event_and_alert(self) -> None:
        import src.dns_detector.alerts as _alerts_mod

        orig = _alerts_mod._stderr
        _alerts_mod._stderr = MagicMock()
        try:
            monitor = _monitor()
            monitor._on_packet(_response("example.com", "1.2.3.4"))
            monitor._on_packet(_response("example.com", "9.9.9.9"))
            assert monitor.event_logger.total >= 1
            ip_change_events = [
                e for e in monitor.event_logger.events
                if e.event_type == DNSEventType.IP_CHANGE
            ]
            assert len(ip_change_events) == 1
            # IP_CHANGE + MULTIPLE_IPS both fire as high-severity alerts
            assert monitor.alert_manager.total_alerts >= 1
        finally:
            _alerts_mod._stderr = orig


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSWatchCLI:
    def test_dns_watch_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dns-watch", "--help"])
        assert result.exit_code == 0
        assert "dns" in result.output.lower()

    def test_dns_watch_without_root_shows_permission_panel(self) -> None:
        runner = CliRunner()
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["dns-watch"])
        assert result.exit_code == 1
        assert "Permission Error" in result.output

    def test_dns_watch_appears_in_top_level_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "dns-watch" in result.output
