"""
UDP protocol parser.

Handles IPv4/UDP packets that are not recognised by a higher-level
parser (DNS).  The DNSParser is checked first in the dispatcher,
so any packet that reaches UDPParser contains a non-DNS UDP payload.
"""
from __future__ import annotations

from datetime import datetime

from scapy.layers.inet import IP, UDP
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


class UDPParser(BaseParser):
    """Parses IPv4 / UDP packets."""

    @staticmethod
    def can_parse(packet: Packet) -> bool:
        return bool(packet.haslayer(IP) and packet.haslayer(UDP))

    @staticmethod
    def parse(packet: Packet) -> ParsedPacket:
        ip = packet[IP]
        udp = packet[UDP]

        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        sport = int(udp.sport)
        dport = int(udp.dport)
        payload = _get_raw_payload(packet)

        return ParsedPacket(
            timestamp=datetime.now(),
            protocol=Protocol.UDP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            length=len(packet),
            summary=f"{src_ip}:{sport} → {dst_ip}:{dport}",
            payload=payload,
        )
