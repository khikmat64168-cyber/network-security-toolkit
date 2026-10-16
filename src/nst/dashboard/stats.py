"""
Thread-safe metrics container for the live dashboard.

DashboardStats is written from the packet-capture thread and read by
the Rich Live refresh thread.  All mutations are protected by a single
Lock; get_snapshot() returns a frozen DashboardSnapshot so the renderer
never observes partially-updated state.
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Tuple


@dataclass
class PacketRow:
    """One row in the recent-packets table."""
    elapsed: float    # seconds since session start
    src: str          # "ip:port" or bare ip
    dst: str
    protocol: str     # Protocol.value string, e.g. "TCP"
    length: int
    info: str


@dataclass(frozen=True)
class DashboardSnapshot:
    """Immutable point-in-time copy of DashboardStats."""
    elapsed: float
    total_packets: int
    total_bytes: int
    pps: float
    protocol_counts: Dict[str, int]
    top_sources: List[Tuple[str, int]]
    top_destinations: List[Tuple[str, int]]
    alert_count: int
    recent: List[PacketRow]


class DashboardStats:
    """
    Accumulates real-time packet metrics in a thread-safe way.

    record_packet() and record_alert() are called from the capture thread.
    get_snapshot() is called from the Rich Live refresh thread.
    A single Lock serialises all access.
    """

    MAX_RECENT: int = 100  # ring-buffer capacity; render shows the last 20

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._protocol_counter: Counter[str] = Counter()
        self._src_counter: Counter[str] = Counter()
        self._dst_counter: Counter[str] = Counter()
        self._alert_count: int = 0
        self._recent: Deque[PacketRow] = deque(maxlen=self.MAX_RECENT)

    # ── Write side (capture thread) ──────────────────────────────────────

    def record_packet(self, parsed: object) -> None:
        """Record one ParsedPacket.  Accepts any object with the ParsedPacket fields."""
        with self._lock:
            self._total_packets += 1
            length: int = getattr(parsed, "length", 0)
            self._total_bytes += length

            proto_val: str = getattr(
                getattr(parsed, "protocol", "OTHER"), "value", "OTHER"
            )
            self._protocol_counter[proto_val] += 1

            src_ip: str = getattr(parsed, "src_ip", "") or ""
            dst_ip: str = getattr(parsed, "dst_ip", "") or ""
            src_port = getattr(parsed, "src_port", None)
            dst_port = getattr(parsed, "dst_port", None)

            if src_ip:
                self._src_counter[src_ip] += 1
            if dst_ip:
                self._dst_counter[dst_ip] += 1

            src = f"{src_ip}:{src_port}" if src_port is not None else (src_ip or "—")
            dst = f"{dst_ip}:{dst_port}" if dst_port is not None else (dst_ip or "—")

            self._recent.append(PacketRow(
                elapsed=time.monotonic() - self._start,
                src=src,
                dst=dst,
                protocol=proto_val,
                length=length,
                info=getattr(parsed, "summary", "") or "",
            ))

    def record_alert(self) -> None:
        """Increment the alert counter shown in the dashboard footer."""
        with self._lock:
            self._alert_count += 1

    # ── Read side (Rich Live refresh thread) ─────────────────────────────

    def get_snapshot(self) -> DashboardSnapshot:
        """Return a frozen point-in-time copy of all current metrics."""
        with self._lock:
            elapsed = time.monotonic() - self._start
            pps = self._total_packets / elapsed if elapsed > 0 else 0.0
            return DashboardSnapshot(
                elapsed=elapsed,
                total_packets=self._total_packets,
                total_bytes=self._total_bytes,
                pps=pps,
                protocol_counts=dict(self._protocol_counter.most_common()),
                top_sources=self._src_counter.most_common(10),
                top_destinations=self._dst_counter.most_common(10),
                alert_count=self._alert_count,
                recent=list(self._recent)[-20:],
            )
