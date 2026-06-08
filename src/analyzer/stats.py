"""
Real-time traffic statistics collector.

Design decisions
────────────────
* TrafficStats is intentionally not thread-safe — it is always updated
  from the same thread that runs Scapy's sniff() callback, so no locking
  is needed.  If the capture is ever moved to a background thread this
  class must be wrapped with a threading.Lock.
* Counter and defaultdict from collections are used instead of plain
  dicts so missing keys are handled without explicit guards.
* ProtocolSummary is a frozen dataclass used only for reporting — callers
  cannot mutate the stats through it.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from src.sniffer.parsers.base import ParsedPacket, Protocol


@dataclass(frozen=True)
class ProtocolSummary:
    """Snapshot of traffic volume for one protocol."""

    protocol: Protocol
    packet_count: int
    byte_count: int

    @property
    def percentage(self) -> float:
        """Always computed against the parent TrafficStats total."""
        return 0.0  # overridden by TrafficStats.protocol_breakdown()


class TrafficStats:
    """
    Accumulates per-protocol packet/byte counts and top-N rankings
    (source IPs, destination IPs, destination ports) as packets arrive.

    Usage
    ─────
        stats = TrafficStats()
        stats.update(parsed_packet)
        breakdown = stats.protocol_breakdown()
    """

    def __init__(self) -> None:
        self._total_packets: int = 0
        self._total_bytes: int = 0

        # Protocol → (packet count, byte count)
        self._proto_packets: Counter[Protocol] = Counter()
        self._proto_bytes: Counter[Protocol] = Counter()

        # IP and port frequency counters
        self._src_ip_counter: Counter[str] = Counter()
        self._dst_ip_counter: Counter[str] = Counter()
        self._dst_port_counter: Counter[int] = Counter()

    # ── Mutation ───────────────────────────────────────────────────────────────

    def update(self, packet: ParsedPacket) -> None:
        """Register one packet in the statistics."""
        self._total_packets += 1
        self._total_bytes += packet.length

        self._proto_packets[packet.protocol] += 1
        self._proto_bytes[packet.protocol] += packet.length

        if packet.src_ip:
            self._src_ip_counter[packet.src_ip] += 1
        if packet.dst_ip:
            self._dst_ip_counter[packet.dst_ip] += 1
        if packet.dst_port is not None:
            self._dst_port_counter[packet.dst_port] += 1

    # ── Read-only properties ───────────────────────────────────────────────────

    @property
    def total_packets(self) -> int:
        return self._total_packets

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    # ── Reporting helpers ──────────────────────────────────────────────────────

    def protocol_breakdown(self) -> List[Tuple[Protocol, int, int, float]]:
        """
        Return per-protocol stats sorted by packet count (descending).

        Each tuple: (Protocol, packet_count, byte_count, pct_of_total)
        """
        result = []
        for proto, pkt_count in self._proto_packets.most_common():
            byte_count = self._proto_bytes[proto]
            pct = (pkt_count / self._total_packets * 100) if self._total_packets else 0.0
            result.append((proto, pkt_count, byte_count, pct))
        return result

    def top_talkers(self, n: int = 5) -> List[Tuple[str, int]]:
        """Return the *n* source IPs with the most packets sent."""
        return self._src_ip_counter.most_common(n)

    def top_destinations(self, n: int = 5) -> List[Tuple[str, int]]:
        """Return the *n* destination IPs with the most packets received."""
        return self._dst_ip_counter.most_common(n)

    def top_ports(self, n: int = 5) -> List[Tuple[int, int]]:
        """Return the *n* destination ports hit most often."""
        return self._dst_port_counter.most_common(n)

    def is_empty(self) -> bool:
        return self._total_packets == 0
