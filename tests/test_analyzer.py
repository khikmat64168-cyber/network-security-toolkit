"""
Unit tests for the traffic analysis module (Phase 3).

All tests use hand-crafted ParsedPacket instances — no live capture needed.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from src.analyzer.credentials import CredentialDetector, CredentialFinding
from src.analyzer.engine import AnalysisEngine
from src.analyzer.stats import TrafficStats
from src.analyzer.threats import ThreatDetector, ThreatEvent
from src.core.config import AnalyzerConfig
from src.sniffer.parsers.base import ParsedPacket, Protocol


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_packet(
    protocol: Protocol = Protocol.TCP,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 12345,
    dst_port: int = 80,
    length: int = 100,
    payload: bytes = b"",
    extra: dict | None = None,
) -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        summary="test",
        payload=payload,
        extra=extra or {},
    )


# ──────────────────────────────────────────────────────────────────────────────
# TrafficStats
# ──────────────────────────────────────────────────────────────────────────────

class TestTrafficStats:
    def test_starts_empty(self) -> None:
        stats = TrafficStats()
        assert stats.total_packets == 0
        assert stats.total_bytes == 0
        assert stats.is_empty() is True

    def test_update_increments_totals(self) -> None:
        stats = TrafficStats()
        stats.update(_make_packet(length=200))
        assert stats.total_packets == 1
        assert stats.total_bytes == 200

    def test_update_multiple_packets(self) -> None:
        stats = TrafficStats()
        for _ in range(5):
            stats.update(_make_packet(length=100))
        assert stats.total_packets == 5
        assert stats.total_bytes == 500

    def test_protocol_breakdown_counts(self) -> None:
        stats = TrafficStats()
        stats.update(_make_packet(protocol=Protocol.TCP))
        stats.update(_make_packet(protocol=Protocol.TCP))
        stats.update(_make_packet(protocol=Protocol.UDP))
        breakdown = {p: cnt for p, cnt, _, _ in stats.protocol_breakdown()}
        assert breakdown[Protocol.TCP] == 2
        assert breakdown[Protocol.UDP] == 1

    def test_protocol_breakdown_sorted_by_count(self) -> None:
        stats = TrafficStats()
        stats.update(_make_packet(protocol=Protocol.UDP))
        for _ in range(3):
            stats.update(_make_packet(protocol=Protocol.TCP))
        top = stats.protocol_breakdown()[0][0]
        assert top == Protocol.TCP

    def test_top_talkers(self) -> None:
        stats = TrafficStats()
        for _ in range(3):
            stats.update(_make_packet(src_ip="1.2.3.4"))
        stats.update(_make_packet(src_ip="5.6.7.8"))
        talkers = dict(stats.top_talkers(5))
        assert talkers["1.2.3.4"] == 3
        assert talkers["5.6.7.8"] == 1

    def test_top_ports(self) -> None:
        stats = TrafficStats()
        for _ in range(4):
            stats.update(_make_packet(dst_port=443))
        stats.update(_make_packet(dst_port=80))
        ports = dict(stats.top_ports(5))
        assert ports[443] == 4
        assert ports[80] == 1

    def test_is_empty_false_after_update(self) -> None:
        stats = TrafficStats()
        stats.update(_make_packet())
        assert stats.is_empty() is False


# ──────────────────────────────────────────────────────────────────────────────
# CredentialDetector
# ──────────────────────────────────────────────────────────────────────────────

class TestCredentialDetector:
    def test_no_findings_for_empty_payload(self) -> None:
        detector = CredentialDetector()
        pkt = _make_packet(payload=b"")
        assert detector.scan(pkt) == []

    def test_detects_http_basic_auth(self) -> None:
        import base64
        creds = base64.b64encode(b"admin:secret123").decode()
        payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        detector = CredentialDetector()
        findings = detector.scan(_make_packet(payload=payload))
        assert len(findings) == 1
        assert findings[0].kind == "HTTP Basic Auth"
        assert findings[0].username == "admin"
        assert findings[0].password == "secret123"

    def test_http_basic_auth_extracts_src_dst(self) -> None:
        import base64
        creds = base64.b64encode(b"user:pass").decode()
        payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        detector = CredentialDetector()
        findings = detector.scan(
            _make_packet(payload=payload, src_ip="192.168.1.1", dst_ip="10.0.0.1")
        )
        assert findings[0].src_ip == "192.168.1.1"
        assert findings[0].dst_ip == "10.0.0.1"

    def test_detects_http_post_credentials(self) -> None:
        payload = (
            b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n"
            b"username=john&password=hunter2"
        )
        detector = CredentialDetector()
        findings = detector.scan(_make_packet(payload=payload))
        assert len(findings) == 1
        assert findings[0].kind == "HTTP POST Credentials"
        assert findings[0].username == "john"
        assert findings[0].password == "hunter2"

    def test_detects_ftp_password_single_packet(self) -> None:
        payload = b"USER bob\r\nPASS s3cr3t\r\n"
        detector = CredentialDetector()
        findings = detector.scan(_make_packet(payload=payload, src_ip="10.1.1.1"))
        ftp = [f for f in findings if f.kind == "FTP Password"]
        assert len(ftp) == 1
        assert ftp[0].username == "bob"
        assert ftp[0].password == "s3cr3t"

    def test_ftp_cross_packet_pairing(self) -> None:
        detector = CredentialDetector()
        pkt_user = _make_packet(payload=b"USER alice\r\n", src_ip="10.1.1.2")
        pkt_pass = _make_packet(payload=b"PASS wonderland\r\n", src_ip="10.1.1.2")
        detector.scan(pkt_user)
        findings = detector.scan(pkt_pass)
        ftp = [f for f in findings if f.kind == "FTP Password"]
        assert len(ftp) == 1
        assert ftp[0].username == "alice"
        assert ftp[0].password == "wonderland"

    def test_no_false_positive_on_plain_tcp(self) -> None:
        detector = CredentialDetector()
        findings = detector.scan(_make_packet(payload=b"\x00\x01\x02\x03binary data"))
        assert findings == []


# ──────────────────────────────────────────────────────────────────────────────
# ThreatDetector
# ──────────────────────────────────────────────────────────────────────────────

class TestThreatDetector:
    def test_no_threats_for_normal_traffic(self) -> None:
        detector = ThreatDetector(port_scan_threshold=10)
        threats = detector.analyze(_make_packet(dst_port=80))
        assert threats == []

    def test_detects_port_scan_after_threshold(self) -> None:
        detector = ThreatDetector(port_scan_threshold=5)
        threats: list[ThreatEvent] = []
        for port in range(1, 7):
            threats.extend(detector.analyze(_make_packet(src_ip="1.2.3.4", dst_port=port)))
        scan_events = [t for t in threats if t.threat_type == "port_scan"]
        assert len(scan_events) == 1
        assert scan_events[0].src_ip == "1.2.3.4"
        assert scan_events[0].severity == "high"

    def test_port_scan_alert_fires_only_once(self) -> None:
        detector = ThreatDetector(port_scan_threshold=3)
        all_threats: list[ThreatEvent] = []
        for port in range(1, 20):
            all_threats.extend(
                detector.analyze(_make_packet(src_ip="9.9.9.9", dst_port=port))
            )
        scan_alerts = [t for t in all_threats if t.threat_type == "port_scan"]
        assert len(scan_alerts) == 1

    def test_detects_dns_tunneling(self) -> None:
        long_query = "a" * 60 + ".evil.example.com"
        detector = ThreatDetector()
        pkt = _make_packet(
            protocol=Protocol.DNS,
            dst_port=53,
            extra={"query_name": long_query},
        )
        threats = detector.analyze(pkt)
        dns_threats = [t for t in threats if t.threat_type == "dns_tunneling"]
        assert len(dns_threats) == 1
        assert dns_threats[0].severity == "medium"

    def test_no_dns_tunnel_alert_for_normal_query(self) -> None:
        detector = ThreatDetector()
        pkt = _make_packet(
            protocol=Protocol.DNS,
            dst_port=53,
            extra={"query_name": "google.com"},
        )
        threats = detector.analyze(pkt)
        assert all(t.threat_type != "dns_tunneling" for t in threats)

    def test_detects_suspicious_port(self) -> None:
        detector = ThreatDetector()
        threats = detector.analyze(_make_packet(dst_port=4444))
        susp = [t for t in threats if t.threat_type == "suspicious_port"]
        assert len(susp) == 1
        assert susp[0].severity == "medium"

    def test_no_alert_for_benign_port(self) -> None:
        detector = ThreatDetector()
        threats = detector.analyze(_make_packet(dst_port=443))
        assert all(t.threat_type != "suspicious_port" for t in threats)


# ──────────────────────────────────────────────────────────────────────────────
# AnalysisEngine
# ──────────────────────────────────────────────────────────────────────────────

class TestAnalysisEngine:
    def _default_engine(self) -> AnalysisEngine:
        config = AnalyzerConfig(
            detect_credentials=True,
            suspicious_port_scan_threshold=5,
            alert_on_suspicious=True,
        )
        return AnalysisEngine(config)

    def test_process_updates_stats(self) -> None:
        engine = self._default_engine()
        engine.process(_make_packet(length=500))
        assert engine.stats.total_packets == 1
        assert engine.stats.total_bytes == 500

    def test_process_multiple_packets(self) -> None:
        engine = self._default_engine()
        for _ in range(10):
            engine.process(_make_packet())
        assert engine.stats.total_packets == 10

    def test_process_does_not_raise_on_bad_packet(self) -> None:
        engine = self._default_engine()
        bad = _make_packet(payload=b"\xff\xfe invalid binary \x00\x00")
        engine.process(bad)   # must not raise

    def test_credential_detection_disabled(self) -> None:
        config = AnalyzerConfig(detect_credentials=False, alert_on_suspicious=False)
        engine = AnalysisEngine(config)
        import base64
        creds = base64.b64encode(b"admin:pass").decode()
        payload = f"GET / HTTP/1.1\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
        engine.process(_make_packet(payload=payload))
        assert engine.alerts.credential_count == 0

    def test_threat_detection_disabled(self) -> None:
        config = AnalyzerConfig(detect_credentials=False, alert_on_suspicious=False)
        engine = AnalysisEngine(config)
        for port in range(1, 20):
            engine.process(_make_packet(src_ip="1.1.1.1", dst_port=port))
        assert engine.alerts.threat_count == 0
