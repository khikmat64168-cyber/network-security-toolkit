"""
Capture sensors for the web dashboard.

A sensor wraps one existing NST capture pipeline and runs it on a
background thread:

    traffic → PacketCapture + ParserDispatcher + AnalysisEngine
    arp     → ARPMonitor
    dns     → DNSMonitor
    mac     → MACMonitor

Design decisions
────────────────
* The pipelines are reused unchanged; they are only wired with
  listener=EventStore.add and console_alerts=False, so detection logic
  is identical to the CLI.
* Each sensor owns copies of its config sections — starting a sensor
  with a different interface never mutates the shared AppConfig.
* Every metric comes from the running pipeline (packet counters,
  DashboardStats, detector tables).  A sensor that has never run
  reports nothing rather than zeros dressed up as data.
* Capture permission is probed by actually opening (and immediately
  closing) a capture socket — euid alone is wrong in both directions
  (Linux capabilities, macOS ChmodBPF).
* Detector tables are plain dicts mutated by the sniffer thread;
  _snapshot() retries the read if a concurrent insert interrupts it.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple, TypeVar

from nst.core.config import AppConfig
from nst.core.exceptions import CaptureError, InsufficientPermissionsError
from nst.core.logger import get_logger
from nst.web.events import EventStore

logger = get_logger(__name__)

T = TypeVar("T")

SENSOR_KINDS = ("traffic", "arp", "dns", "mac")
SENSOR_LABELS = {
    "traffic": "Traffic analyzer",
    "arp": "ARP spoofing detector",
    "dns": "DNS spoofing detector",
    "mac": "MAC flooding detector",
}
_TIMELINE_SECONDS = 300


# ──────────────────────────────────────────────────────────────────────────────
# Capture permission probe
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CaptureProbe:
    allowed: bool
    code: str          # "ok" | "permission_denied" | "interface_error" | "capture_unavailable"
    message: str


def probe_capture(interface: Optional[str]) -> CaptureProbe:
    """Open and close a capture socket on *interface* to test real access."""
    try:
        import scapy.sendrecv  # noqa: F401 — initialises conf.L2listen
        from scapy.config import conf

        if conf.L2listen is None:
            return CaptureProbe(False, "capture_unavailable",
                                "Scapy has no capture backend on this system")
        sock = conf.L2listen(iface=interface) if interface else conf.L2listen()
        sock.close()
    except PermissionError:
        return CaptureProbe(
            False, "permission_denied",
            "Opening a capture socket was denied. Restart nst web with sudo "
            "(or grant capture rights, e.g. CAP_NET_RAW / access_bpf).",
        )
    except (ValueError, OSError) as exc:
        return CaptureProbe(False, "interface_error", f"Cannot open interface: {exc}")
    except Exception as exc:   # noqa: BLE001
        return CaptureProbe(False, "capture_unavailable", f"Capture backend error: {exc}")
    return CaptureProbe(True, "ok", "Capture socket opened successfully")


# ──────────────────────────────────────────────────────────────────────────────
# Traffic timeline
# ──────────────────────────────────────────────────────────────────────────────

class TrafficTimeline:
    """Per-second packet / byte counts for the last few minutes."""

    def __init__(self, seconds: int = _TIMELINE_SECONDS) -> None:
        self._lock = threading.Lock()
        self._buckets: Deque[List[int]] = deque(maxlen=seconds)   # [epoch_sec, packets, bytes]

    def add(self, length: int, now: Optional[float] = None) -> None:
        second = int(now if now is not None else time.time())
        with self._lock:
            if self._buckets and self._buckets[-1][0] == second:
                self._buckets[-1][1] += 1
                self._buckets[-1][2] += length
            else:
                self._buckets.append([second, 1, length])

    def series(self) -> List[Dict[str, int]]:
        with self._lock:
            return [{"t": t, "packets": p, "bytes": b} for t, p, b in self._buckets]


# ──────────────────────────────────────────────────────────────────────────────
# Sensors
# ──────────────────────────────────────────────────────────────────────────────

class Sensor:
    """Lifecycle wrapper around one capture pipeline run."""

    def __init__(self, kind: str, store: EventStore) -> None:
        self.kind = kind
        self._store = store
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._runner: Optional[Any] = None       # object with .stop()
        self.state = "idle"                        # idle | running | stopping | stopped | error
        self.interface: Optional[str] = None
        self.bpf_filter = ""
        self.started_at: Optional[str] = None
        self.stopped_at: Optional[str] = None
        self.error: Optional[Dict[str, str]] = None
        self.events = 0
        self.on_change: Optional[Callable[["Sensor"], None]] = None

    # ── Lifecycle ───────────────────────────────────────────────────────────

    @property
    def active(self) -> bool:
        return self.state in ("running", "stopping")

    def start(self, config: AppConfig, interface: Optional[str], bpf_filter: str) -> None:
        with self._lock:
            if self.active:
                raise RuntimeError(f"{SENSOR_LABELS[self.kind]} is already running")
            self.interface = interface
            self.bpf_filter = bpf_filter
            self.started_at = _now()
            self.stopped_at = None
            self.error = None
            self.events = 0
            self._runner, target = self._build(config, interface, bpf_filter)
            self.state = "running"
            self._thread = threading.Thread(
                target=self._run, args=(target,), name=f"nst-sensor-{self.kind}", daemon=True
            )
            self._thread.start()
        self._changed()

    def stop(self) -> None:
        with self._lock:
            if not self.active:
                return
            self.state = "stopping"
            runner = self._runner
        self._changed()
        if runner is not None:
            runner.stop()

    def join(self, timeout: float = 5.0) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def _run(self, target: Callable[[], None]) -> None:
        try:
            target()
            self._finish("stopped", None)
        except InsufficientPermissionsError as exc:
            self._finish("error", {"code": "permission_denied", "message": str(exc)})
        except CaptureError as exc:
            self._finish("error", {"code": "capture_failed", "message": str(exc)})
        except Exception as exc:   # noqa: BLE001
            logger.debug("Sensor %s crashed", self.kind, exc_info=True)
            self._finish("error", {"code": "internal_error", "message": str(exc)})

    def _finish(self, state: str, error: Optional[Dict[str, str]]) -> None:
        with self._lock:
            self.state = state
            self.error = error
            self.stopped_at = _now()
        self._changed()

    def _changed(self) -> None:
        if self.on_change is not None:
            try:
                self.on_change(self)
            except Exception:   # noqa: BLE001
                pass

    def _record(self, raw: Any) -> None:
        self._store.add(raw, self.kind)
        self.events += 1

    # ── Overridden per kind ─────────────────────────────────────────────────

    def _build(
        self, config: AppConfig, interface: Optional[str], bpf_filter: str
    ) -> Tuple[Any, Callable[[], None]]:
        raise NotImplementedError

    @property
    def packets(self) -> Optional[int]:
        return None

    def details(self) -> Dict[str, Any]:
        return {}

    # ── Serialisation ───────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "kind": self.kind,
                "label": SENSOR_LABELS[self.kind],
                "state": self.state,
                "interface": self.interface,
                "bpf_filter": self.bpf_filter if self.kind == "traffic" else None,
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "error": self.error,
                "packets": self.packets if self.started_at else None,
                "events": self.events if self.started_at else None,
            }


class TrafficSensor(Sensor):
    def __init__(self, store: EventStore) -> None:
        super().__init__("traffic", store)
        self._capture: Optional[Any] = None
        self._stats: Optional[Any] = None
        self._engine: Optional[Any] = None
        self.timeline = TrafficTimeline()

    def _build(
        self, config: AppConfig, interface: Optional[str], bpf_filter: str
    ) -> Tuple[Any, Callable[[], None]]:
        from scapy.packet import Packet as ScapyPacket

        from nst.analyzer.engine import AnalysisEngine
        from nst.dashboard.stats import DashboardStats
        from nst.sniffer.capture import PacketCapture
        from nst.sniffer.parsers import ParserDispatcher

        sniffer_cfg = replace(config.sniffer, filter=bpf_filter, packet_count=0, output_file=None)
        network_cfg = replace(config.network, interface=interface, capture_timeout=0)
        capture = PacketCapture(sniffer_cfg, network_cfg)
        stats = DashboardStats()
        timeline = TrafficTimeline()

        def on_finding(finding: Any) -> None:
            stats.record_alert()
            self._record(finding)

        engine = AnalysisEngine(config.analyzer, listener=on_finding, console_alerts=False)

        def on_packet(pkt: object) -> None:
            if not isinstance(pkt, ScapyPacket):
                return
            parsed = ParserDispatcher.dispatch(pkt)
            stats.record_packet(parsed)
            timeline.add(parsed.length)
            engine.process(parsed)

        self._capture, self._stats, self._engine, self.timeline = capture, stats, engine, timeline
        return capture, lambda: capture.start(on_packet)

    @property
    def packets(self) -> Optional[int]:
        return self._capture.packet_count if self._capture is not None else None

    def details(self) -> Dict[str, Any]:
        if self._stats is None or self._engine is None:
            return {}
        snap = self._stats.get_snapshot()
        traffic = self._engine.stats
        return {
            "elapsed": snap.elapsed,
            "total_packets": snap.total_packets,
            "total_bytes": snap.total_bytes,
            "pps": snap.pps,
            "protocols": snap.protocol_counts,
            "top_sources": [{"ip": ip, "packets": n} for ip, n in snap.top_sources],
            "top_destinations": [{"ip": ip, "packets": n} for ip, n in snap.top_destinations],
            "top_ports": [{"port": p, "packets": n}
                          for p, n in _snapshot(lambda: traffic.top_ports(8))],
            "recent": [
                {"elapsed": r.elapsed, "src": r.src, "dst": r.dst, "protocol": r.protocol,
                 "length": r.length, "info": r.info}
                for r in snap.recent
            ],
            "timeline": self.timeline.series(),
        }


class _MonitorSensor(Sensor):
    """Shared plumbing for the ARP / DNS / MAC monitors."""

    def __init__(self, kind: str, store: EventStore) -> None:
        super().__init__(kind, store)
        self._monitor: Optional[Any] = None

    def _make_monitor(self, config: AppConfig, network_cfg: Any) -> Any:
        raise NotImplementedError

    def _build(
        self, config: AppConfig, interface: Optional[str], bpf_filter: str
    ) -> Tuple[Any, Callable[[], None]]:
        network_cfg = replace(config.network, interface=interface)
        monitor = self._make_monitor(config, network_cfg)
        self._monitor = monitor
        return monitor, monitor.start

    @property
    def packets(self) -> Optional[int]:
        return self._monitor.packet_count if self._monitor is not None else None


class ARPSensor(_MonitorSensor):
    def __init__(self, store: EventStore) -> None:
        super().__init__("arp", store)

    def _make_monitor(self, config: AppConfig, network_cfg: Any) -> Any:
        from nst.arp_detector.monitor import ARPMonitor

        arp_cfg = replace(config.arp_detector, trusted_ips=list(config.arp_detector.trusted_ips))
        return ARPMonitor(arp_cfg, network_cfg, listener=self._record, console_alerts=False)

    def details(self) -> Dict[str, Any]:
        if self._monitor is None:
            return {}
        entries = _snapshot(self._monitor.table.all_entries)
        return {"bindings": [
            {"ip": e.ip, "mac": e.mac, "packets": e.packet_count, "trusted": e.is_trusted,
             "first_seen": e.first_seen.isoformat(), "last_seen": e.last_seen.isoformat()}
            for e in entries
        ]}


class DNSSensor(_MonitorSensor):
    def __init__(self, store: EventStore) -> None:
        super().__init__("dns", store)

    def _make_monitor(self, config: AppConfig, network_cfg: Any) -> Any:
        from nst.dns_detector.monitor import DNSMonitor

        dns_cfg = replace(config.dns_detector,
                          trusted_domains=list(config.dns_detector.trusted_domains))
        return DNSMonitor(dns_cfg, network_cfg, listener=self._record, console_alerts=False)

    def details(self) -> Dict[str, Any]:
        if self._monitor is None:
            return {}
        entries = _snapshot(self._monitor.table.all_entries)

        def ips(entry: Any) -> List[str]:
            return sorted(_snapshot(lambda: set(entry.ips_seen)))

        return {"resolutions": [
            {"domain": e.domain, "current_ip": e.current_ip,
             "ips_seen": ips(e),
             "packets": e.packet_count, "last_seen": e.last_seen.isoformat()}
            for e in entries
        ]}


class MACSensor(_MonitorSensor):
    def __init__(self, store: EventStore) -> None:
        super().__init__("mac", store)
        self._table_limit: Optional[int] = None

    def _make_monitor(self, config: AppConfig, network_cfg: Any) -> Any:
        from nst.mac_detector.monitor import MACMonitor

        self._table_limit = config.mac_detector.table_limit
        return MACMonitor(replace(config.mac_detector), network_cfg,
                          listener=self._record, console_alerts=False)

    def details(self) -> Dict[str, Any]:
        if self._monitor is None:
            return {}
        entries = _snapshot(self._monitor.table.all_entries)
        top = sorted(entries, key=lambda e: e.packet_count, reverse=True)[:25]
        return {
            "unique_macs": len(entries),
            "table_limit": self._table_limit,
            "top_macs": [{"mac": e.mac, "packets": e.packet_count} for e in top],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Manager
# ──────────────────────────────────────────────────────────────────────────────

class SensorManager:
    """Owns one sensor of each kind for the lifetime of the web server."""

    def __init__(self, config: AppConfig, store: EventStore) -> None:
        self.config = config
        self.store = store
        self.sensors: Dict[str, Sensor] = {
            "traffic": TrafficSensor(store),
            "arp": ARPSensor(store),
            "dns": DNSSensor(store),
            "mac": MACSensor(store),
        }

    def get(self, kind: str) -> Sensor:
        if kind not in self.sensors:
            raise KeyError(kind)
        return self.sensors[kind]

    def statuses(self) -> List[Dict[str, Any]]:
        return [s.status() for s in self.sensors.values()]

    def stop_all(self, timeout: float = 5.0) -> None:
        for sensor in self.sensors.values():
            sensor.stop()
        for sensor in self.sensors.values():
            sensor.join(timeout)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _snapshot(read: Callable[[], T], attempts: int = 5) -> T:
    """Call *read*, retrying if a concurrent mutation interrupts iteration."""
    for _ in range(attempts - 1):
        try:
            return read()
        except RuntimeError:   # "dictionary changed size during iteration"
            time.sleep(0.001)
    return read()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
