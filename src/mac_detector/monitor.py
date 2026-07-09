"""Live MAC flooding monitor — captures Ethernet frames and runs detection."""
from __future__ import annotations

from typing import TYPE_CHECKING

from scapy.layers.l2 import Ether

from src.mac_detector.alerts import MACAlertManager
from src.mac_detector.detector import FloodDetector
from src.mac_detector.events import EventLogger
from src.mac_detector.table import MACTable

if TYPE_CHECKING:
    from scapy.packet import Packet as ScapyPacket
    from src.core.config import MACDetectorConfig, NetworkConfig


class MACMonitor:
    """
    Captures raw Ethernet frames and feeds source MACs into FloodDetector.

    Usage
    ─────
        monitor = MACMonitor(cfg.mac_detector, cfg.network)
        monitor.start()   # blocks until Ctrl-C
    """

    def __init__(
        self,
        config: "MACDetectorConfig",
        network_config: "NetworkConfig",
    ) -> None:
        self._config = config
        self._network = network_config

        self.table = MACTable()
        self.detector = FloodDetector(
            table=self.table,
            threshold=config.flood_threshold,
            window_secs=config.window_secs,
            table_limit=config.table_limit,
        )
        self.alert_manager = MACAlertManager()
        self.event_logger = EventLogger()
        self.packet_count: int = 0

    def start(self) -> None:
        from scapy.sendrecv import sniff

        kwargs: dict = {
            "prn": self._on_packet,
            "store": False,
        }
        if self._network.interface:
            kwargs["iface"] = self._network.interface

        sniff(**kwargs)

    def _on_packet(self, packet: "ScapyPacket") -> None:
        self.packet_count += 1

        if not packet.haslayer(Ether):
            return

        mac: str = packet[Ether].src
        events = self.detector.analyze(mac)

        for event in events:
            self.event_logger.log(event)
            self.alert_manager.show_alert(event)
