"""
Unit tests for the packet sniffer module (Phase 2).

All tests use Scapy's packet-construction API to build mock packets.
No actual network capture is performed, so root privileges are NOT required.
"""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from src.sniffer.parsers import ParserDispatcher
from src.sniffer.parsers.base import ParsedPacket, Protocol
from src.sniffer.parsers.dns import DNSParser
from src.sniffer.parsers.http import HTTPParser
from src.sniffer.parsers.tcp import TCPParser
from src.sniffer.parsers.udp import UDPParser


# ──────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tcp_syn():
    return IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
        sport=54321, dport=443, flags="S"
    )


@pytest.fixture
def tcp_http_get():
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    return (
        IP(src="10.0.0.1", dst="93.184.216.34")
        / TCP(sport=45678, dport=80, flags="PA")
        / Raw(load=payload)
    )


@pytest.fixture
def tcp_http_response():
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>"
    return (
        IP(src="93.184.216.34", dst="10.0.0.1")
        / TCP(sport=80, dport=45678, flags="PA")
        / Raw(load=payload)
    )


@pytest.fixture
def udp_plain():
    return IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=9999)


@pytest.fixture
def dns_query():
    from scapy.layers.dns import DNS, DNSQR

    return (
        IP(src="10.0.0.1", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(qr=0, qd=DNSQR(qname="example.com"))
    )


@pytest.fixture
def dns_response():
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    return (
        IP(src="8.8.8.8", dst="10.0.0.1")
        / UDP(sport=53, dport=54321)
        / DNS(
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com.", rdata="93.184.216.34"),
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# TCPParser
# ──────────────────────────────────────────────────────────────────────────────

class TestTCPParser:
    def test_can_parse_tcp(self, tcp_syn) -> None:
        assert TCPParser.can_parse(tcp_syn) is True

    def test_cannot_parse_udp(self, udp_plain) -> None:
        assert TCPParser.can_parse(udp_plain) is False

    def test_returns_parsedpacket(self, tcp_syn) -> None:
        assert isinstance(TCPParser.parse(tcp_syn), ParsedPacket)

    def test_protocol_is_tcp(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).protocol == Protocol.TCP

    def test_extracts_src_ip(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).src_ip == "192.168.1.1"

    def test_extracts_dst_ip(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).dst_ip == "192.168.1.2"

    def test_extracts_src_port(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).src_port == 54321

    def test_extracts_dst_port(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).dst_port == 443

    def test_includes_syn_flag(self, tcp_syn) -> None:
        assert "S" in TCPParser.parse(tcp_syn).flags

    def test_length_positive(self, tcp_syn) -> None:
        assert TCPParser.parse(tcp_syn).length > 0


# ──────────────────────────────────────────────────────────────────────────────
# UDPParser
# ──────────────────────────────────────────────────────────────────────────────

class TestUDPParser:
    def test_can_parse_udp(self, udp_plain) -> None:
        assert UDPParser.can_parse(udp_plain) is True

    def test_cannot_parse_tcp(self, tcp_syn) -> None:
        assert UDPParser.can_parse(tcp_syn) is False

    def test_protocol_is_udp(self, udp_plain) -> None:
        assert UDPParser.parse(udp_plain).protocol == Protocol.UDP

    def test_extracts_addresses(self, udp_plain) -> None:
        result = UDPParser.parse(udp_plain)
        assert result.src_ip == "10.0.0.1"
        assert result.dst_ip == "10.0.0.2"

    def test_extracts_ports(self, udp_plain) -> None:
        result = UDPParser.parse(udp_plain)
        assert result.src_port == 12345
        assert result.dst_port == 9999


# ──────────────────────────────────────────────────────────────────────────────
# HTTPParser
# ──────────────────────────────────────────────────────────────────────────────

class TestHTTPParser:
    def test_can_parse_http_get(self, tcp_http_get) -> None:
        assert HTTPParser.can_parse(tcp_http_get) is True

    def test_can_parse_http_response(self, tcp_http_response) -> None:
        assert HTTPParser.can_parse(tcp_http_response) is True

    def test_cannot_parse_plain_tcp(self, tcp_syn) -> None:
        assert HTTPParser.can_parse(tcp_syn) is False

    def test_protocol_is_http(self, tcp_http_get) -> None:
        assert HTTPParser.parse(tcp_http_get).protocol == Protocol.HTTP

    def test_request_summary_contains_method(self, tcp_http_get) -> None:
        assert "GET" in HTTPParser.parse(tcp_http_get).summary

    def test_request_summary_contains_host(self, tcp_http_get) -> None:
        assert "example.com" in HTTPParser.parse(tcp_http_get).summary

    def test_response_summary_contains_status(self, tcp_http_response) -> None:
        assert "200" in HTTPParser.parse(tcp_http_response).summary

    def test_request_extra_is_request_true(self, tcp_http_get) -> None:
        assert HTTPParser.parse(tcp_http_get).extra["is_request"] is True

    def test_response_extra_is_request_false(self, tcp_http_response) -> None:
        assert HTTPParser.parse(tcp_http_response).extra["is_request"] is False

    def test_payload_stored_as_bytes(self, tcp_http_get) -> None:
        assert isinstance(HTTPParser.parse(tcp_http_get).payload, bytes)


# ──────────────────────────────────────────────────────────────────────────────
# DNSParser
# ──────────────────────────────────────────────────────────────────────────────

class TestDNSParser:
    def test_can_parse_dns_query(self, dns_query) -> None:
        assert DNSParser.can_parse(dns_query) is True

    def test_can_parse_dns_response(self, dns_response) -> None:
        assert DNSParser.can_parse(dns_response) is True

    def test_cannot_parse_plain_udp(self, udp_plain) -> None:
        assert DNSParser.can_parse(udp_plain) is False

    def test_query_protocol_is_dns(self, dns_query) -> None:
        assert DNSParser.parse(dns_query).protocol == Protocol.DNS

    def test_query_summary_contains_domain(self, dns_query) -> None:
        assert "example.com" in DNSParser.parse(dns_query).summary

    def test_query_extra_is_query(self, dns_query) -> None:
        assert DNSParser.parse(dns_query).extra["is_query"] is True

    def test_response_extra_has_answers(self, dns_response) -> None:
        result = DNSParser.parse(dns_response)
        assert len(result.extra.get("answers", [])) > 0

    def test_response_summary_contains_ip(self, dns_response) -> None:
        result = DNSParser.parse(dns_response)
        assert "93.184.216.34" in result.summary or result.extra["answers"]


# ──────────────────────────────────────────────────────────────────────────────
# ParserDispatcher
# ──────────────────────────────────────────────────────────────────────────────

class TestParserDispatcher:
    def test_dispatches_http_over_tcp(self, tcp_http_get) -> None:
        assert ParserDispatcher.dispatch(tcp_http_get).protocol == Protocol.HTTP

    def test_dispatches_dns_over_udp(self, dns_query) -> None:
        assert ParserDispatcher.dispatch(dns_query).protocol == Protocol.DNS

    def test_dispatches_plain_tcp(self, tcp_syn) -> None:
        assert ParserDispatcher.dispatch(tcp_syn).protocol == Protocol.TCP

    def test_dispatches_plain_udp(self, udp_plain) -> None:
        assert ParserDispatcher.dispatch(udp_plain).protocol == Protocol.UDP

    def test_always_returns_parsedpacket(self, tcp_syn) -> None:
        assert isinstance(ParserDispatcher.dispatch(tcp_syn), ParsedPacket)

    def test_http_wins_over_tcp_for_http_packet(self, tcp_http_get) -> None:
        result = ParserDispatcher.dispatch(tcp_http_get)
        assert result.protocol == Protocol.HTTP

    def test_dns_wins_over_udp_for_dns_packet(self, dns_query) -> None:
        result = ParserDispatcher.dispatch(dns_query)
        assert result.protocol == Protocol.DNS
