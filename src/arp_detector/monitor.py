"""
ARP packet monitor — continuous ARP traffic inspection.

ARPMonitor is the top-level coordinator for Phase 4.  It:
    1. Seeds the ARPTable from the OS ARP cache at startup
       (so previously-poisoned entries are detected immediately).
    2. Starts a Scapy BPF-filtered sniff loop ("arp") on the chosen
       interface.
    3. Passes every ARP packet through SpoofingDetector.
    4. Logs all ARPEvents via EventLogger.
    5. Calls ARPAlertManager.show_alert() for high/critical events.

Threading model
───────────────
start() blocks the calling thread — the same pattern used by
PacketCapture in Phase 2.  The caller (CLI command) runs it directly
and handles KeyboardInterrupt to print the session summary.

Scapy stop_filter
─────────────────
Scapy's stop_filter is called after every packet.  When stop() sets
_stop_event, the next packet (or the timeout) causes sniff() to return.
"""
from __future__ import annotations

import threading
from typing import Any

from src.arp_detector.alerts import ARPAlertManager
from src.arp_detector.detector import SpoofingDetector
from src.arp_detector.events import EventLogger
from src.arp_detector.table import ARPTable
from src.core.config import ArpDetectorConfig, NetworkConfig
from src.core.exceptions import CaptureError, InsufficientPermissionsError
from src.core.logger import get_logger

logger = get_logger(__name__)


class ARPMonitor:
    """
    Coordinates ARP monitoring for one arp-watch session.

    Usage
    ─────
        monitor = ARPMonitor(config.arp_detector, config.network)
        try:
            monitor.start()          # blocks
        except KeyboardInterrupt:
            pass
        # access results:
        monitor.event_logger.events
        monitor.table.all_entries()
    """

    def __init__(
        self,
        config: ArpDetectorConfig,
        network_config: NetworkConfig,
    ) -> None:
        self._config = config
        self._net_cfg = network_config
        self._stop_event = threading.Event()

        self._table = ARPTable(trusted_ips=config.trusted_ips)
        self._detector = SpoofingDetector(
            table=self._table,
            gateway_ip=config.gateway_ip,
        )
        self._event_logger = EventLogger()
        self._alert_manager = ARPAlertManager()
        self._packet_count = 0

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Begin ARP monitoring.  Blocks until stop() is called or Ctrl-C.

        Raises InsufficientPermissionsError if the process cannot open a
        raw socket (requires root / CAP_NET_RAW).
        Raises CaptureError for other Scapy / OS failures.
        """
        from scapy.sendrecv import sniff

        # Pre-populate the table from the OS ARP cache so we start with
        # a known-good baseline rather than treating every entry as new.
        imported = self._table.load_from_system()
        if imported:
            logger.info("Seeded ARP table with %d entries from OS cache", imported)

        iface = self._net_cfg.interface or None
        logger.info("Starting ARP monitor on interface %s", iface or "default")

        try:
            sniff(
                iface=iface,
                filter="arp",
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            raise InsufficientPermissionsError(
                "Root privileges are required to capture ARP packets."
            ) from exc
        except OSError as exc:
            raise CaptureError(f"ARP capture failed: {exc}") from exc

    def stop(self) -> None:
        """Signal the monitoring loop to exit after the next packet."""
        self._stop_event.set()

    # ── Properties ──────────────────────────────────────────────────────────

    @property
    def table(self) -> ARPTable:
        return self._table

    @property
    def event_logger(self) -> EventLogger:
        return self._event_logger

    @property
    def alert_manager(self) -> ARPAlertManager:
        return self._alert_manager

    @property
    def packet_count(self) -> int:
        return self._packet_count

    # ── Internal ────────────────────────────────────────────────────────────

    def _on_packet(self, packet: Any) -> None:
        """Scapy prn callback — called from the sniff loop for every packet."""
        from scapy.layers.l2 import ARP

        if not packet.haslayer(ARP):
            return

        self._packet_count += 1
        arp = packet[ARP]

        try:
            events = self._detector.analyze(arp)
        except Exception as exc:
            logger.debug("Detector error on packet %d: %s", self._packet_count, exc)
            return

        for event in events:
            self._event_logger.log(event)
            if event.severity in ("high", "critical"):
                self._alert_manager.show_alert(event)
