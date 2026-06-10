"""
Network threat detection engine.

Detects:
  - Port scanning     : one source IP hitting many distinct destination ports
  - DNS tunneling     : abnormally long DNS query names (> 50 chars)
  - Suspicious ports  : traffic to ports commonly used by malware / RATs

Design decisions
────────────────
* Each ThreatDetector instance maintains per-source-IP state so it can
  detect patterns that span multiple packets (e.g. port scans).
* _alerted_scanners prevents the same source IP from generating an
  unbounded stream of port-scan alerts — one alert per IP per session.
* Severity levels: low → medium → high → critical.
* ThreatEvent is frozen so callers cannot mutate it after the fact.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from src.core.logger import get_logger
from src.sniffer.parsers.base import ParsedPacket, Protocol

logger = get_logger(__name__)

# Ports associated with common RATs, backdoors, and C2 frameworks
_SUSPICIOUS_PORTS: frozenset[int] = frozenset(
    {
        1080,   # SOCKS proxy (often abused)
        4444,   # Metasploit default
        5555,   # ADB / Android debug
        6666,   # IRC (often used by botnets)
        6667,   # IRC
        8888,   # Common reverse-shell port
        9001,   # Tor ORPort
        31337,  # Elite / Back Orifice
    }
)

_DNS_TUNNEL_THRESHOLD = 50   # label characters in a single query name


@dataclass(frozen=True)
class ThreatEvent:
    """A security event detected by ThreatDetector."""

    threat_type: str    # "port_scan" | "dns_tunneling" | "suspicious_port"
    src_ip: str
    dst_ip: str
    severity: str       # "low" | "medium" | "high" | "critical"
    description: str
    details: Dict[str, Any] = field(default_factory=dict)


class ThreatDetector:
    """
    Stateful threat detector — must be kept alive across packets so that
    cross-packet patterns (like port scans) can be accumulated.

    Usage
    ─────
        detector = ThreatDetector(port_scan_threshold=10)
        threats = detector.analyze(parsed_packet)
        for t in threats:
            print(t.description)
    """

    def __init__(self, port_scan_threshold: int = 10) -> None:
        self._port_scan_threshold = port_scan_threshold

        # src_ip → set of destination ports contacted
        self._port_hits: Dict[str, Set[int]] = defaultdict(set)

        # src_ip → set of unique destination IPs contacted (for sweep detection)
        self._dst_hits: Dict[str, Set[str]] = defaultdict(set)

        # src IPs that have already triggered a port-scan alert this session
        self._alerted_scanners: Set[str] = set()

    def analyze(self, packet: ParsedPacket) -> List[ThreatEvent]:
        """Analyse *packet* and return any threats detected."""
        threats: List[ThreatEvent] = []

        threats.extend(self._check_port_scan(packet))
        threats.extend(self._check_dns_tunneling(packet))
        threats.extend(self._check_suspicious_port(packet))

        for t in threats:
            logger.warning("THREAT [%s] %s", t.severity.upper(), t.description)

        return threats

    # ── Detection methods ──────────────────────────────────────────────────────

    def _check_port_scan(self, packet: ParsedPacket) -> List[ThreatEvent]:
        if packet.dst_port is None or not packet.src_ip:
            return []

        ports = self._port_hits[packet.src_ip]
        ports.add(packet.dst_port)

        if packet.dst_ip:
            self._dst_hits[packet.src_ip].add(packet.dst_ip)

        if (
            len(ports) >= self._port_scan_threshold
            and packet.src_ip not in self._alerted_scanners
        ):
            self._alerted_scanners.add(packet.src_ip)
            return [
                ThreatEvent(
                    threat_type="port_scan",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    severity="high",
                    description=(
                        f"Port scan detected — {packet.src_ip} has contacted "
                        f"{len(ports)} unique ports"
                    ),
                    details={
                        "unique_ports_count": len(ports),
                        "sample_ports": sorted(ports)[:15],
                        "unique_dst_ips": len(self._dst_hits[packet.src_ip]),
                    },
                )
            ]
        return []

    def _check_dns_tunneling(self, packet: ParsedPacket) -> List[ThreatEvent]:
        if packet.protocol != Protocol.DNS:
            return []

        query_name: str = packet.extra.get("query_name", "")
        if not query_name or len(query_name) <= _DNS_TUNNEL_THRESHOLD:
            return []

        return [
            ThreatEvent(
                threat_type="dns_tunneling",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                severity="medium",
                description=(
                    f"Possible DNS tunneling — unusually long query "
                    f"({len(query_name)} chars) from {packet.src_ip}"
                ),
                details={
                    "query_name": query_name,
                    "query_length": len(query_name),
                    "threshold": _DNS_TUNNEL_THRESHOLD,
                },
            )
        ]

    def _check_suspicious_port(self, packet: ParsedPacket) -> List[ThreatEvent]:
        port = packet.dst_port
        if port is None or port not in _SUSPICIOUS_PORTS:
            return []

        return [
            ThreatEvent(
                threat_type="suspicious_port",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                severity="medium",
                description=(
                    f"Traffic to suspicious port {port} "
                    f"({packet.src_ip} → {packet.dst_ip}:{port})"
                ),
                details={"port": port},
            )
        ]
