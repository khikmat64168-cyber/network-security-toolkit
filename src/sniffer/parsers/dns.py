"""
DNS protocol parser.

Design decisions
────────────────
* Handles both DNS queries (qr=0) and responses (qr=1).
* Answer extraction iterates the linked-list structure in Scapy's DNS
  layer with a hard cap of 20 records to prevent pathological inputs
  from looping indefinitely.
* All field accesses are wrapped in try/except — malformed or truncated
  DNS packets must not crash the capture loop.
* Transport port is detected dynamically (DNS can run over UDP or TCP).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from scapy.packet import Packet

from src.sniffer.parsers.base import BaseParser, ParsedPacket, Protocol

_MAX_ANSWER_RECORDS = 20


def _decode_qname(qname: Any) -> str:
    """Safely decode a DNS qname bytes object to a dotted-label string."""
    try:
        if isinstance(qname, bytes):
            return qname.decode("utf-8", errors="replace").rstrip(".")
        return str(qname).rstrip(".")
    except Exception:
        return ""


def _extract_answers(dns: Any) -> List[str]:
    """
    Walk the DNS answer section and return rdata strings.

    Handles both Scapy APIs:
      - Scapy 2.6+: dns.an is a list  (PacketListField)
      - Scapy < 2.6: dns.an is a linked Packet chain
    """
    answers: List[str] = []
    try:
        an = dns.an
        if isinstance(an, list):
            # Scapy 2.6+ PacketListField
            for rr in an[:_MAX_ANSWER_RECORDS]:
                try:
                    rdata = getattr(rr, "rdata", None)
                    if rdata is not None:
                        answers.append(str(rdata))
                except Exception:
                    pass
        else:
            # Scapy < 2.6 linked-list chain
            rr = an
            for _ in range(_MAX_ANSWER_RECORDS):
                if rr is None or not hasattr(rr, "rrname"):
                    break
                try:
                    rdata = getattr(rr, "rdata", None)
                    if rdata is not None:
                        answers.append(str(rdata))
                except Exception:
                    pass
                rr = getattr(rr, "payload", None)
    except Exception:
        pass
    return answers


def _get_transport_ports(packet: Packet) -> tuple[Optional[int], Optional[int]]:
    """Return (src_port, dst_port) from the transport layer, or (None, None)."""
    try:
        from scapy.layers.inet import UDP

        if packet.haslayer(UDP):
            udp = packet[UDP]
            return int(udp.sport), int(udp.dport)
    except Exception:
        pass
    try:
        from scapy.layers.inet import TCP

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            return int(tcp.sport), int(tcp.dport)
    except Exception:
        pass
    return None, None


class DNSParser(BaseParser):
    """Parses DNS query and response packets (over UDP or TCP)."""

    @staticmethod
    def can_parse(packet: Packet) -> bool:
        return bool(packet.haslayer(DNS) and packet.haslayer(IP))

    @staticmethod
    def parse(packet: Packet) -> ParsedPacket:
        ip = packet[IP]
        dns = packet[DNS]

        is_query = int(getattr(dns, "qr", 0)) == 0

        query_name = ""
        try:
            qd = dns.qd
            if qd is not None:
                if isinstance(qd, list):
                    # Scapy 2.6+ PacketListField
                    if qd:
                        query_name = _decode_qname(qd[0].qname)
                else:
                    # Scapy < 2.6 single record
                    query_name = _decode_qname(qd.qname)
        except Exception:
            pass

        answers: List[str] = [] if is_query else _extract_answers(dns)

        if is_query:
            summary = f"DNS? {query_name}" if query_name else "DNS query"
        else:
            if answers:
                answer_preview = ", ".join(answers[:3])
                summary = (
                    f"DNS {query_name} → {answer_preview}"
                    if query_name
                    else f"DNS → {answer_preview}"
                )
            else:
                summary = f"DNS {query_name} (no answer)" if query_name else "DNS response"

        src_port, dst_port = _get_transport_ports(packet)

        return ParsedPacket(
            timestamp=datetime.now(),
            protocol=Protocol.DNS,
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            src_port=src_port,
            dst_port=dst_port,
            length=len(packet),
            summary=summary,
            extra={
                "is_query": is_query,
                "query_name": query_name,
                "answers": answers,
            },
        )
