"""
DNS spoofing and cache-poisoning detection logic.

Detection methods
─────────────────
1. IP change       — A domain that previously resolved to IP X now
                     resolves to IP Y.  Severity: "high".
2. Unsolicited     — A DNS response arrives with no matching prior query
                     (transaction ID not seen).  Severity: "medium".
                     Requires track_queries=True (default).
3. Zero TTL        — A response sets TTL=0, forcing all caches to expire
                     the record immediately — a classic poisoning vector.
                     Severity: "medium".
4. Multiple IPs    — The same domain resolves to 2+ distinct IPs in one
                     session.  May indicate DNS-based load balancing or
                     active poisoning.  Severity: "high".
                     Fires once per domain per session.

Design notes
────────────
* analyze() accepts any object with .qr, .id, .qd, .an attributes so
  tests can pass real Scapy DNS layers without needing raw sockets.
* Trusted domains bypass all checks — the table is still updated so
  ip_count() stays accurate, but no events are generated.
* Pending queries expire after _QUERY_TTL_SECS seconds to prevent the
  dict from growing without bound on long sessions.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from src.dns_detector.events import DNSEvent, DNSEventType
from src.dns_detector.table import DNSTable

_QUERY_TTL_SECS: int = 10


class DNSSpoofingDetector:
    """
    Analyses Scapy DNS layers against the DNSTable and returns zero or
    more DNSEvent objects describing anomalies.

    Usage
    ─────
        detector = DNSSpoofingDetector(table, track_queries=True)
        events   = detector.analyze(dns_layer, src_ip, dst_ip)
    """

    def __init__(self, table: DNSTable, track_queries: bool = True) -> None:
        self._table = table
        self._track_queries = track_queries
        # (client_ip, dns_transaction_id) → (domain, monotonic_timestamp)
        self._pending: Dict[Tuple[str, int], Tuple[str, float]] = {}
        # domains for which MULTIPLE_IPS was already emitted this session
        self._multi_alerted: Set[str] = set()

    # ── Public API ──────────────────────────────────────────────────────

    def analyze(self, dns: Any, src_ip: str, dst_ip: str) -> List[DNSEvent]:
        """
        Analyse one Scapy DNS layer.

        dns    — Scapy DNS object (needs .qr, .id, .qd, .an attributes).
        src_ip — sender of this DNS packet.
        dst_ip — recipient of this DNS packet.
        Returns a (possibly empty) list of DNSEvent objects.
        """
        try:
            qr = int(dns.qr)
        except Exception:
            return []

        if qr == 0:
            if self._track_queries:
                self._record_query(dns, src_ip)
            return []

        return self._analyze_response(dns, src_ip, dst_ip)

    # ── Private helpers ─────────────────────────────────────────────────

    def _record_query(self, dns: Any, client_ip: str) -> None:
        self._expire_old_queries()
        try:
            qd = dns.qd
            # Scapy 2.6+ changed qd/an/ns/ar to PacketListField (list).
            if isinstance(qd, list):
                qd = qd[0] if qd else None
            if qd is None:
                return
            qname = qd.qname
            domain = (
                qname.decode("utf-8", errors="replace")
                if isinstance(qname, bytes)
                else str(qname)
            ).rstrip(".")
            self._pending[(client_ip, int(dns.id))] = (domain, time.monotonic())
        except Exception:
            pass

    def _analyze_response(
        self, dns: Any, src_ip: str, dst_ip: str
    ) -> List[DNSEvent]:
        self._expire_old_queries()
        events: List[DNSEvent] = []

        # dst_ip of a response = the client that sent the query.
        query_key = (dst_ip, int(dns.id))
        matched = self._pending.pop(query_key, None)
        is_unsolicited = matched is None and self._track_queries

        a_records = _extract_a_records(dns)
        if not a_records:
            return []

        if is_unsolicited:
            domain = a_records[0][0]
            events.append(DNSEvent(
                event_type=DNSEventType.UNSOLICITED,
                domain=domain,
                new_ip=a_records[0][1],
                src_ip=src_ip,
                timestamp=datetime.now(),
                severity="medium",
                description=(
                    f"DNS response for '{domain}' arrived with no matching "
                    f"query (id={dns.id:#06x})"
                ),
            ))

        for domain, ip, ttl in a_records:
            if self._table.is_trusted(domain):
                self._table.update(domain, ip)
                continue

            old_ip = self._table.update(domain, ip)

            if old_ip:
                events.append(DNSEvent(
                    event_type=DNSEventType.IP_CHANGE,
                    domain=domain,
                    new_ip=ip,
                    old_ip=old_ip,
                    src_ip=src_ip,
                    timestamp=datetime.now(),
                    severity="high",
                    description=f"DNS IP changed for '{domain}': {old_ip} → {ip}",
                ))

            if ttl == 0:
                events.append(DNSEvent(
                    event_type=DNSEventType.ZERO_TTL,
                    domain=domain,
                    new_ip=ip,
                    src_ip=src_ip,
                    timestamp=datetime.now(),
                    severity="medium",
                    ttl=ttl,
                    description=(
                        f"DNS response for '{domain}' ({ip}) has TTL=0 "
                        f"— forces immediate cache expiry"
                    ),
                ))

            if (
                self._table.ip_count(domain) >= 2
                and domain not in self._multi_alerted
            ):
                self._multi_alerted.add(domain)
                all_ips = sorted(self._table.known_ips(domain))
                events.append(DNSEvent(
                    event_type=DNSEventType.MULTIPLE_IPS,
                    domain=domain,
                    new_ip=ip,
                    src_ip=src_ip,
                    timestamp=datetime.now(),
                    severity="high",
                    description=(
                        f"'{domain}' resolved to {len(all_ips)} IPs this session:"
                        f" {', '.join(all_ips)}"
                    ),
                ))

        return events

    def _expire_old_queries(self) -> None:
        cutoff = time.monotonic() - _QUERY_TTL_SECS
        stale = [k for k, (_, ts) in self._pending.items() if ts < cutoff]
        for k in stale:
            del self._pending[k]


def _extract_a_records(dns: Any) -> List[Tuple[str, str, int]]:
    """
    Return (domain, ip, ttl) for every A record in the DNS answer section.

    Scapy 2.6+ changed dns.an from a chained DNSRR payload to a
    PacketListField (a plain list).  We handle both forms.
    """
    results: List[Tuple[str, str, int]] = []
    try:
        from scapy.layers.dns import DNSRR

        answers = dns.an
        # Scapy 2.6+: PacketListField → list; older: single DNSRR or None.
        if not isinstance(answers, list):
            answers = [answers] if answers is not None else []

        for an in answers:
            if not isinstance(an, DNSRR) or int(an.type) != 1:
                continue
            rrname = an.rrname
            domain = (
                rrname.decode("utf-8", errors="replace")
                if isinstance(rrname, bytes)
                else str(rrname)
            ).rstrip(".")
            results.append((domain, str(an.rdata), int(an.ttl)))
    except Exception:
        pass
    return results
