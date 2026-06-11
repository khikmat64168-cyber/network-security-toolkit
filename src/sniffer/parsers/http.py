"""
HTTP/1.x protocol parser.

Design decisions
────────────────
* Only inspects plaintext HTTP — HTTPS (port 443) payload is opaque
  TLS ciphertext, so we deliberately skip it here.
* Port-based pre-check comes before payload inspection so we avoid
  parsing the raw bytes of every TCP packet.
* Credential detection (Authorization headers, POST body keywords) is
  intentionally left for Phase 3's analyzer layer, keeping this parser
  focused solely on structural extraction.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from src.sniffer.parsers.base import BaseParser, ParsedPacket, Protocol

_HTTP_REQUEST_METHODS: tuple[bytes, ...] = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)
_HTTP_RESPONSE_PREFIX = b"HTTP/"

# Ports on which we expect to see cleartext HTTP
_HTTP_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 8888, 3000, 8443})


def _get_raw(packet: Packet) -> bytes:
    from scapy.packet import Raw

    if packet.haslayer(Raw):
        try:
            return bytes(packet[Raw].load)
        except Exception:
            return b""
    return b""


def _is_http_payload(raw: bytes) -> bool:
    return any(raw.startswith(m) for m in _HTTP_REQUEST_METHODS) or raw.startswith(
        _HTTP_RESPONSE_PREFIX
    )


def _extract_request_line(raw: bytes) -> Tuple[str, str]:
    """Return (method, path) from the HTTP request line, or ('', '')."""
    try:
        first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return "", ""


def _extract_status_code(raw: bytes) -> str:
    """Return the HTTP status code string from a response, or ''."""
    try:
        first_line = raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            return parts[1]
    except Exception:
        pass
    return ""


def _extract_host(raw: bytes) -> str:
    """Return the value of the Host header, or ''."""
    try:
        match = re.search(rb"(?i)Host:\s*([^\r\n]+)", raw)
        if match:
            return match.group(1).decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    return ""


class HTTPParser(BaseParser):
    """
    Parses plaintext HTTP/1.x requests and responses.

    Identified by: TCP packet on a known HTTP port whose payload
    starts with a recognised HTTP method or 'HTTP/' response prefix.
    """

    @staticmethod
    def can_parse(packet: Packet) -> bool:
        if not bool(packet.haslayer(IP) and packet.haslayer(TCP)):
            return False
        tcp = packet[TCP]
        if tcp.sport not in _HTTP_PORTS and tcp.dport not in _HTTP_PORTS:
            return False
        raw = _get_raw(packet)
        return bool(raw) and _is_http_payload(raw)

    @staticmethod
    def parse(packet: Packet) -> ParsedPacket:
        ip = packet[IP]
        tcp = packet[TCP]
        raw = _get_raw(packet)

        is_request = any(raw.startswith(m) for m in _HTTP_REQUEST_METHODS)

        if is_request:
            method, path = _extract_request_line(raw)
            host = _extract_host(raw)
            summary = f"{method} {host}{path}" if host else f"{method} {path}"
        else:
            status = _extract_status_code(raw)
            summary = f"HTTP {status}" if status else "HTTP Response"

        return ParsedPacket(
            timestamp=datetime.now(),
            protocol=Protocol.HTTP,
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            length=len(packet),
            summary=summary.strip(),
            payload=raw,
            extra={"is_request": is_request},
        )
