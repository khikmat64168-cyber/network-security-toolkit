"""
ARP spoofing and MITM detection logic.

Detection methods
─────────────────
1. MAC change       — A known IP appears with a different MAC address.
                      Severity is "critical" if the IP is the configured
                      gateway, otherwise "high".
2. Gratuitous ARP   — An ARP reply (op=2) where psrc == pdst.  Legitimate
                      hosts send these during boot / IP conflict probing, but
                      they are also the primary spoofing vector.  A single
                      gratuitous ARP is "medium"; when the same sender has
                      previously triggered a MAC change in the same session
                      the severity escalates to "high".
3. MITM suspected   — When both a gateway MAC change AND gratuitous ARP
                      from the same host are detected in one session, a
                      separate MITM_SUSPECTED event is emitted at "critical".

Design notes
────────────
* analyze() is pure from the caller's perspective — it reads from the
  ARPTable only, and writes back via table.update().  Side effects are
  limited to returning ARPEvent objects; the caller (ARPMonitor) decides
  when to log and alert.
* trusted_ips bypass all checks — the detector returns [] immediately for
  these hosts.
* Scapy ARP field names: hwsrc/hwdst (MAC), psrc/pdst (IP), op (1=request,
  2=reply).  We accept any object that has these attributes so tests can
  pass a simple namespace instead of a real Scapy packet.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import List, Optional, Set

from src.arp_detector.events import ARPEvent, ARPEventType
from src.arp_detector.table import ARPTable


class SpoofingDetector:
    """
    Analyses Scapy ARP packets against the ARPTable and returns zero or
    more ARPEvent objects describing anomalies found.

    Usage
    ─────
        detector = SpoofingDetector(table, gateway_ip="192.168.1.1")
        events = detector.analyze(scapy_arp_packet)
    """

    def __init__(
        self,
        table: ARPTable,
        gateway_ip: Optional[str] = None,
    ) -> None:
        self._table = table
        self._gateway_ip = gateway_ip
        # Track senders that have triggered a gratuitous ARP this session.
        self._gratuitous_senders: Set[str] = set()
        # Track senders that have triggered a MAC change this session.
        self._mac_changed_senders: Set[str] = set()
        # Track senders for which we have already emitted MITM_SUSPECTED.
        self._mitm_alerted: Set[str] = set()
        # Gratuitous ARP count per sender (for storm detection).
        self._gratuitous_count: Counter[str] = Counter()

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(self, arp) -> List[ARPEvent]:
        """
        Analyse one Scapy ARP layer and return all detected anomalies.

        *arp* must expose: op (int), hwsrc (str), psrc (str), pdst (str).
        Returns an empty list for trusted IPs and for normal traffic.
        """
        psrc: str = arp.psrc
        hwsrc: str = arp.hwsrc
        pdst: str = arp.pdst
        op: int = int(arp.op)

        # Skip hosts the user has explicitly trusted.
        if self._table.is_trusted(psrc):
            self._table.update(psrc, hwsrc)
            return []

        events: List[ARPEvent] = []

        # ── 1. MAC change detection ──────────────────────────────────────
        old_mac = self._table.update(psrc, hwsrc)
        if old_mac:
            is_gateway = psrc == self._gateway_ip
            severity = "critical" if is_gateway else "high"
            event_type = (
                ARPEventType.GATEWAY_MAC_CHANGE
                if is_gateway
                else ARPEventType.MAC_CHANGE
            )
            description = (
                f"MAC address changed for {'gateway ' if is_gateway else ''}"
                f"{psrc}: {old_mac} → {hwsrc}"
            )
            events.append(
                ARPEvent(
                    event_type=event_type,
                    src_ip=psrc,
                    src_mac=hwsrc,
                    dst_ip=pdst,
                    old_mac=old_mac,
                    timestamp=datetime.now(),
                    severity=severity,
                    description=description,
                )
            )
            self._mac_changed_senders.add(psrc)

        # ── 2. Gratuitous ARP detection (op=2, psrc==pdst) ───────────────
        if op == 2 and psrc == pdst:
            self._gratuitous_count[hwsrc] += 1
            self._gratuitous_senders.add(psrc)

            # Escalate if same sender already triggered a MAC change.
            severity = "high" if psrc in self._mac_changed_senders else "medium"
            events.append(
                ARPEvent(
                    event_type=ARPEventType.GRATUITOUS_ARP,
                    src_ip=psrc,
                    src_mac=hwsrc,
                    dst_ip=pdst,
                    old_mac=None,
                    timestamp=datetime.now(),
                    severity=severity,
                    description=(
                        f"Gratuitous ARP reply from {psrc} ({hwsrc})"
                        f" — count: {self._gratuitous_count[hwsrc]}"
                    ),
                )
            )

        # ── 3. MITM suspected — combined signal ─────────────────────────
        if (
            psrc in self._mac_changed_senders
            and psrc in self._gratuitous_senders
            and psrc not in self._mitm_alerted
        ):
            self._mitm_alerted.add(psrc)
            events.append(
                ARPEvent(
                    event_type=ARPEventType.MITM_SUSPECTED,
                    src_ip=psrc,
                    src_mac=hwsrc,
                    dst_ip=pdst,
                    old_mac=None,
                    timestamp=datetime.now(),
                    severity="critical",
                    description=(
                        f"MITM attack suspected: {psrc} ({hwsrc}) has sent both "
                        f"a spoofed ARP reply and a gratuitous ARP this session"
                    ),
                )
            )

        return events
