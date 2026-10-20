"""
Normalized security events for the web dashboard.

Design decisions
────────────────
* Every detector speaks its own dataclass (CredentialFinding,
  ThreatEvent, ARPEvent, DNSEvent, MACEvent).  The dashboard needs one
  shape, so each is mapped onto SecurityEvent — modelled on the CHIMERA
  `security.event` v1 contract: category, severity, summary, asset_ref
  plus structured evidence.  Mapping is lossless for everything except
  secrets.
* Redaction happens here, at the boundary, before anything is stored
  or leaves the process.  Plaintext passwords and the raw context line
  (which for HTTP Basic Auth is the base64-encoded credential pair) are
  never put into a SecurityEvent.
* Credential findings carry no severity of their own; they are mapped
  to "high" — the same weight the CLI gives them with its red panel.
* EventStore is a bounded ring buffer with a monotonically increasing
  sequence number, so clients can resume with `?after=<seq>` and memory
  stays flat during long sessions.
"""
from __future__ import annotations

import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional

from nst.analyzer.credentials import CredentialFinding
from nst.analyzer.threats import ThreatEvent
from nst.arp_detector.events import ARPEvent
from nst.dns_detector.events import DNSEvent
from nst.mac_detector.events import MACEvent

SCHEMA_VERSION = 1
SEVERITIES = ("info", "low", "medium", "high", "critical")
REDACTED = "[redacted]"


@dataclass(frozen=True)
class SecurityEvent:
    """One normalized, redacted security event."""

    id: str
    seq: int
    occurred_at: str            # ISO-8601, UTC
    sensor: str                 # "traffic" | "arp" | "dns" | "mac"
    module: str                 # producing NST module, e.g. "nst.arp_detector"
    category: str               # e.g. "arp.mac_change", "credential.plaintext"
    severity: str               # one of SEVERITIES
    summary: str
    asset_ref: Optional[str]    # primary affected / offending asset (IP, MAC, domain)
    evidence: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# Detector → SecurityEvent mapping
# ──────────────────────────────────────────────────────────────────────────────

DetectorEvent = Any   # CredentialFinding | ThreatEvent | ARPEvent | DNSEvent | MACEvent


def normalize(raw: DetectorEvent, sensor: str, seq: int) -> SecurityEvent:
    """Map one detector event onto a SecurityEvent.  Raises TypeError for unknown types."""
    if isinstance(raw, CredentialFinding):
        return _event(
            seq, sensor, "nst.analyzer", "credential.plaintext", "high",
            f"Plaintext {raw.kind} from {raw.src_ip} to {raw.dst_ip}",
            raw.src_ip,
            {
                "protocol": raw.protocol,
                "kind": raw.kind,
                "src_ip": raw.src_ip,
                "dst_ip": raw.dst_ip,
                "username": raw.username,
                "password": REDACTED,
                "context": REDACTED,
            },
        )
    if isinstance(raw, ThreatEvent):
        return _event(
            seq, sensor, "nst.analyzer", f"threat.{raw.threat_type}", raw.severity,
            raw.description, raw.src_ip,
            {"src_ip": raw.src_ip, "dst_ip": raw.dst_ip, **_jsonable(raw.details)},
        )
    if isinstance(raw, ARPEvent):
        return _event(
            seq, sensor, "nst.arp_detector", f"arp.{raw.event_type.value}", raw.severity,
            raw.description, raw.src_ip,
            {
                "src_ip": raw.src_ip,
                "src_mac": raw.src_mac,
                "dst_ip": raw.dst_ip,
                "old_mac": raw.old_mac,
                "detected_at": raw.timestamp.isoformat(),
            },
        )
    if isinstance(raw, DNSEvent):
        return _event(
            seq, sensor, "nst.dns_detector", f"dns.{raw.event_type.value}", raw.severity,
            raw.description, raw.domain,
            {
                "domain": raw.domain,
                "new_ip": raw.new_ip,
                "old_ip": raw.old_ip,
                "responder_ip": raw.src_ip,
                "ttl": raw.ttl,
                "detected_at": raw.timestamp.isoformat(),
            },
        )
    if isinstance(raw, MACEvent):
        return _event(
            seq, sensor, "nst.mac_detector", f"mac.{raw.event_type.value}", raw.severity,
            raw.description, raw.mac,
            {
                "mac": raw.mac,
                "new_macs_in_window": raw.new_macs_in_window,
                "total_macs": raw.total_macs,
                "detected_at": raw.timestamp.isoformat(),
            },
        )
    raise TypeError(f"Unsupported detector event: {type(raw).__name__}")


def _event(
    seq: int,
    sensor: str,
    module: str,
    category: str,
    severity: str,
    summary: str,
    asset_ref: Optional[str],
    evidence: Dict[str, Any],
) -> SecurityEvent:
    return SecurityEvent(
        id=uuid.uuid4().hex,
        seq=seq,
        occurred_at=datetime.now(timezone.utc).isoformat(),
        sensor=sensor,
        module=module,
        category=category,
        severity=severity if severity in SEVERITIES else "info",
        summary=summary,
        asset_ref=asset_ref or None,
        evidence=evidence,
    )


def _jsonable(value: Any) -> Any:
    """Convert detector detail values (sets, enums, dataclasses …) to JSON types."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = [_jsonable(v) for v in value]
        return sorted(items, key=str) if isinstance(value, (set, frozenset)) else items
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return _jsonable(asdict(value))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


# ──────────────────────────────────────────────────────────────────────────────
# Store
# ──────────────────────────────────────────────────────────────────────────────

class EventStore:
    """
    Thread-safe bounded store of SecurityEvents.

    add() is called from sniffer threads; subscribers are invoked
    synchronously with each new event (they must not block).
    """

    def __init__(self, capacity: int = 5000) -> None:
        self._lock = threading.Lock()
        self._events: Deque[SecurityEvent] = deque(maxlen=capacity)
        self._seq = 0
        self._counts: Dict[str, int] = {s: 0 for s in SEVERITIES}
        self._subscribers: List[Callable[[SecurityEvent], None]] = []

    def add(self, raw: DetectorEvent, sensor: str) -> SecurityEvent:
        with self._lock:
            self._seq += 1
            event = normalize(raw, sensor, self._seq)
            self._events.append(event)
            self._counts[event.severity] += 1
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:   # noqa: BLE001 — a broken subscriber must not stop capture
                pass
        return event

    def subscribe(self, callback: Callable[[SecurityEvent], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def list(
        self,
        after: int = 0,
        limit: int = 200,
        severity: Optional[str] = None,
        sensor: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Newest-last events with seq > *after*, optionally filtered."""
        with self._lock:
            events = [e for e in self._events if e.seq > after]
        if severity:
            events = [e for e in events if e.severity == severity]
        if sensor:
            events = [e for e in events if e.sensor == sensor]
        return events[-limit:]

    def get(self, event_id: str) -> Optional[SecurityEvent]:
        with self._lock:
            return next((e for e in self._events if e.id == event_id), None)

    def counts(self) -> Dict[str, int]:
        """Events per severity since the server started (not capped by capacity)."""
        with self._lock:
            return dict(self._counts)

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq
