"""
DNS packet monitor — continuous DNS traffic inspection.

DNSMonitor is the top-level coordinator for Phase 7.  It:
    1. Starts a Scapy BPF-filtered sniff loop ("udp port 53") on the
       chosen interface.
    2. Passes every DNS response through DNSSpoofingDetector.
    3. Logs all DNSEvents via EventLogger.
    4. Calls DNSAlertManager.show_alert() for high/critical events.

Threading model
───────────────
start() blocks the calling thread — the same pattern used by
PacketCapture (Phase 2) and ARPMonitor (Phase 4).
"""
from __future__ import annotations

import threading
from typing import Any, List, Optional

from src.core.config import DNSDetectorConfig, NetworkConfig
from src.core.exceptions import CaptureError, InsufficientPermissionsError
from src.core.logger import get_logger
from src.dns_detector.alerts import DNSAlertManager
from src.dns_detector.detector import DNSSpoofingDetector
from src.dns_detector.events import EventLogger
from src.dns_detector.table import DNSTable

logger = get_logger(__name__)


class DNSMonitor:
    """
    Coordinates DNS monitoring for one dns-watch session.

    Usage
    ─────
        monitor = DNSMonitor(cfg.dns_detector, cfg.network)
        try:
            monitor.start()        # blocks
        except KeyboardInterrupt:
            pass
        monitor.event_logger.events   # results
    """

    def __init__(
        self,
        config: DNSDetectorConfig,
        network_config: NetworkConfig,
    ) -> None:
        self._config = config
        self._net_cfg = network_config
        self._stop_event = threading.Event()

        self._table = DNSTable(trusted_domains=config.trusted_domains)
        self._detector = DNSSpoofingDetector(
            table=self._table,
            track_queries=config.track_queries,
        )
        self._event_logger = EventLogger()
        self._alert_manager = DNSAlertManager()
        self._packet_count: int = 0

    # ── Public API ──────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Begin DNS monitoring.  Blocks until stop() is called or Ctrl-C.

        Raises InsufficientPermissionsError if the process cannot open a
        raw socket.  Raises CaptureError for other OS-level failures.
        """
        from scapy.sendrecv import sniff

        iface = self._net_cfg.interface or None
        logger.info("Starting DNS monitor on interface %s", iface or "default")

        try:
            sniff(
                iface=iface,
                filter="udp port 53",
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            raise InsufficientPermissionsError(
                "Root privileges are required to capture DNS packets."
            ) from exc
        except OSError as exc:
            raise CaptureError(f"DNS capture failed: {exc}") from exc

    def stop(self) -> None:
        """Signal the monitoring loop to exit after the next packet."""
        self._stop_event.set()

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def table(self) -> DNSTable:
        return self._table

    @property
    def event_logger(self) -> EventLogger:
        return self._event_logger

    @property
    def alert_manager(self) -> DNSAlertManager:
        return self._alert_manager

    @property
    def packet_count(self) -> int:
        return self._packet_count

    # ── Internal ────────────────────────────────────────────────────────

    def _on_packet(self, packet: Any) -> None:
        """Scapy prn callback — called for every captured UDP/53 packet."""
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP

        if not packet.haslayer(DNS):
            return

        self._packet_count += 1
        dns = packet[DNS]
        src_ip = packet[IP].src if packet.haslayer(IP) else ""
        dst_ip = packet[IP].dst if packet.haslayer(IP) else ""

        try:
            events = self._detector.analyze(dns, src_ip, dst_ip)
        except Exception as exc:
            logger.debug(
                "DNS detector error on packet %d: %s", self._packet_count, exc
            )
            return

        for event in events:
            self._event_logger.log(event)
            if event.severity in ("high", "critical"):
                self._alert_manager.show_alert(event)
