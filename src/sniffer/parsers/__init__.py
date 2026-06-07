"""
Protocol parser package.

ParserDispatcher is the single entry point for all packet parsing.
It tries each parser in priority order and returns the first match.

Priority order (important):
    HTTP  before TCP  — HTTP is a TCP specialisation; check it first
    DNS   before UDP  — DNS is a UDP specialisation; check it first
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Type

from scapy.packet import Packet

from src.sniffer.parsers.base import BaseParser, ParsedPacket, Protocol
from src.sniffer.parsers.dns import DNSParser
from src.sniffer.parsers.http import HTTPParser
from src.sniffer.parsers.tcp import TCPParser
from src.sniffer.parsers.udp import UDPParser


def _fallback(packet: Packet) -> ParsedPacket:
    """Minimal ParsedPacket for packets no parser claims."""
    try:
        summary = packet.summary()
    except Exception:
        summary = "Unknown packet"
    return ParsedPacket(
        timestamp=datetime.now(),
        protocol=Protocol.OTHER,
        src_ip="",
        dst_ip="",
        src_port=None,
        dst_port=None,
        length=len(packet),
        summary=summary,
    )


class ParserDispatcher:
    """
    Routes Scapy Packet objects to the appropriate protocol parser.

    Usage
    ─────
        parsed = ParserDispatcher.dispatch(scapy_packet)
    """

    _PARSERS: List[Type[BaseParser]] = [HTTPParser, DNSParser, TCPParser, UDPParser]

    @classmethod
    def dispatch(cls, packet: Packet) -> ParsedPacket:
        """Return a ParsedPacket produced by the first matching parser."""
        for parser_cls in cls._PARSERS:
            try:
                if parser_cls.can_parse(packet):
                    return parser_cls.parse(packet)
            except Exception:
                continue
        return _fallback(packet)


__all__ = [
    "ParserDispatcher",
    "ParsedPacket",
    "Protocol",
    "TCPParser",
    "UDPParser",
    "HTTPParser",
    "DNSParser",
]
