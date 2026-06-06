"""
TCP protocol parser.

Handles IPv4/TCP packets that are not recognised by a higher-level
parser (HTTP).  The HTTPParser is checked first in the dispatcher,
so any packet that reaches TCPParser is pure TCP without HTTP payload.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from src.sniffer.parsers.base import BaseParser, ParsedPacket, Protocol


def _get_raw_payload(packet: Packet) -> bytes:
    """Extract the application-layer payload bytes, or return empty bytes."""
    from scapy.packet import Raw

    if packet.haslayer(Raw):
        try:
            return bytes(packet[Raw].load)
        except Exception:
            return b""
    return b""


def _decode_flags(flags: Any) -> str:
    """Convert Scapy's FlagValue to a human-readable string (e.g. 'S', 'PA')."""
    try:
        return str(flags)
    except Exception:
        return ""


class TCPParser(BaseParser):
    """Parses IPv4 / TCP packets."""

    @staticmethod
    def can_parse(packet: Packet) -> bool:
        return bool(packet.haslayer(IP) and packet.haslayer(TCP))

    @staticmethod
    def parse(packet: Packet) -> ParsedPacket:
        ip = packet[IP]
        tcp = packet[TCP]

        flags = _decode_flags(tcp.flags)
        payload = _get_raw_payload(packet)

        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        sport = int(tcp.sport)
        dport = int(tcp.dport)

        return ParsedPacket(
            timestamp=datetime.now(),
            protocol=Protocol.TCP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            length=len(packet),
            summary=f"{src_ip}:{sport} → {dst_ip}:{dport} [{flags}]",
            payload=payload,
            flags=flags,
        )
