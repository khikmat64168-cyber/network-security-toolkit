"""
Live MAC flooding monitor — captures Ethernet frames and runs detection.

MACMonitor is the top-level coordinator for mac-watch.  It:
    1. Starts a Scapy sniff loop on the chosen interface.
    2. Feeds the source MAC of every Ethernet frame into FloodDetector.
    3. Logs all MACEvents via EventLogger.
    4. Calls MACAlertManager.show_alert() for every event.

Threading model
───────────────
start() blocks the calling thread — the same pattern used by
ARPMonitor and DNSMonitor.  The caller (CLI command) runs it directly
and handles KeyboardInterrupt to print the session summary.
"""
from __future__ import annotations

import threading
from typing import Any

from nst.core.config import MACDetectorConfig, NetworkConfig
from nst.core.exceptions import CaptureError, InsufficientPermissionsError
from nst.core.logger import get_logger
from nst.mac_detector.alerts import MACAlertManager
from nst.mac_detector.detector import FloodDetector
from nst.mac_detector.events import EventLogger
from nst.mac_detector.table import MACTable

logger = get_logger(__name__)


class MACMonitor:
    """
    Captures raw Ethernet frames and feeds source MACs into FloodDetector.

    Usage
    ─────
        monitor = MACMonitor(cfg.mac_detector, cfg.network)
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
        config: MACDetectorConfig,
        network_config: NetworkConfig,
    ) -> None:
        self._config = config
        self._net_cfg = network_config
        self._stop_event = threading.Event()

        self._table = MACTable()
        self._detector = FloodDetector(
            table=self._table,
            threshold=config.flood_threshold,
            window_secs=config.window_secs,
            table_limit=config.table_limit,
        )
        self._alert_manager = MACAlertManager()
        self._event_logger = EventLogger()
        self._packet_count = 0

    # ── Public API ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Begin MAC monitoring.  Blocks until stop() is called or Ctrl-C.

        Raises InsufficientPermissionsError if the process cannot open a
        raw socket (requires root / CAP_NET_RAW).
        Raises CaptureError for other Scapy / OS failures.
        """
        from scapy.sendrecv import sniff

        iface = self._net_cfg.interface or None
        logger.info("Starting MAC monitor on interface %s", iface or "default")

        try:
            sniff(
                iface=iface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            raise InsufficientPermissionsError(
                "Root privileges are required to capture Ethernet frames."
            ) from exc
        except OSError as exc:
            raise CaptureError(f"MAC capture failed: {exc}") from exc

    def stop(self) -> None:
        """Signal the monitoring loop to exit after the next packet."""
        self._stop_event.set()

    # ── Properties ──────────────────────────────────────────────────────────

    @property
    def table(self) -> MACTable:
        return self._table

    @property
    def detector(self) -> FloodDetector:
        return self._detector

    @property
    def event_logger(self) -> EventLogger:
        return self._event_logger

    @property
    def alert_manager(self) -> MACAlertManager:
        return self._alert_manager

    @property
    def packet_count(self) -> int:
        return self._packet_count

    # ── Internal ────────────────────────────────────────────────────────────

    def _on_packet(self, packet: Any) -> None:
        """Scapy prn callback — called from the sniff loop for every frame."""
        from scapy.layers.l2 import Ether

        self._packet_count += 1

        if not packet.haslayer(Ether):
            return

        mac: str = packet[Ether].src
        try:
            events = self._detector.analyze(mac)
        except Exception as exc:
            logger.debug("Detector error on packet %d: %s", self._packet_count, exc)
            return

        for event in events:
            self._event_logger.log(event)
            self._alert_manager.show_alert(event)
