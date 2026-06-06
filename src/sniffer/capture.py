"""
Packet capture engine wrapping Scapy's sniff().

Design decisions
────────────────
* start() blocks the calling thread — the CLI runs it on the main thread
  so that KeyboardInterrupt (Ctrl-C) is delivered naturally by the OS.
* stop_filter lets another thread signal a clean stop after the next
  packet arrives.  If no packets arrive the loop stays open, which is
  acceptable for an interactive security tool.
* PCAP writing uses PcapWriter with sync=True so every packet is flushed
  to disk immediately — no data is lost if the process is killed.
* PermissionError from the OS is re-raised as InsufficientPermissionsError
  so the CLI can present a useful message instead of a raw traceback.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Optional

from scapy.packet import Packet

from src.core.config import NetworkConfig, SnifferConfig
from src.core.exceptions import CaptureError, InsufficientPermissionsError
from src.core.logger import get_logger

logger = get_logger(__name__)


class PacketCapture:
    """
    Scapy-backed packet capture engine.

    Usage
    ─────
        capture = PacketCapture(sniffer_cfg, network_cfg)
        try:
            capture.start(on_packet_callback)   # blocks
        except KeyboardInterrupt:
            pass
        finally:
            print(f"Captured: {capture.packet_count}")
    """

    def __init__(self, config: SnifferConfig, network_config: NetworkConfig) -> None:
        self._config = config
        self._net_cfg = network_config
        self._stop_event = threading.Event()
        self._packet_count: int = 0
        self._pcap_writer: Optional[Any] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    @property
    def packet_count(self) -> int:
        """Total packets captured so far."""
        return self._packet_count

    def start(self, on_packet: Callable[[Packet], None]) -> None:
        """
        Begin capturing packets.  Blocks until the capture ends.

        The capture ends when:
          - The configured packet count is reached (sniffer.packet_count > 0)
          - The configured timeout expires  (network.capture_timeout > 0)
          - stop() is called from another thread
          - The user presses Ctrl-C  (KeyboardInterrupt propagates to caller)

        Args:
            on_packet: Callback invoked with each captured Scapy Packet.

        Raises:
            InsufficientPermissionsError: Process lacks raw socket access.
            CaptureError: Capture failed for another OS-level reason.
        """
        from scapy.sendrecv import sniff

        self._stop_event.clear()
        self._packet_count = 0

        if self._config.output_file:
            self._open_pcap_writer(self._config.output_file)

        iface: Optional[str] = self._net_cfg.interface or None
        bpf_filter: Optional[str] = self._config.filter or None
        count: int = self._config.packet_count              # 0 = unlimited in Scapy
        timeout: Optional[int] = (
            self._net_cfg.capture_timeout
            if self._net_cfg.capture_timeout > 0
            else None
        )

        logger.info(
            "Capture starting — iface=%s  filter=%r  count=%s  timeout=%s",
            iface or "auto",
            bpf_filter,
            count or "∞",
            f"{timeout}s" if timeout else "∞",
        )

        def _handle(pkt: Packet) -> None:
            self._packet_count += 1
            if self._pcap_writer is not None:
                try:
                    self._pcap_writer.write(pkt)
                except Exception as exc:
                    logger.debug("PCAP write error: %s", exc)
            try:
                on_packet(pkt)
            except Exception as exc:
                logger.debug("on_packet callback raised: %s", exc)

        try:
            sniff(
                iface=iface,
                prn=_handle,
                filter=bpf_filter,
                count=count,
                store=False,
                promisc=self._net_cfg.promiscuous,
                stop_filter=lambda _p: self._stop_event.is_set(),
                timeout=timeout,
            )
        except PermissionError as exc:
            raise InsufficientPermissionsError(
                "Raw socket access denied — re-run with sudo."
            ) from exc
        except OSError as exc:
            raise CaptureError(f"Capture OS error: {exc}") from exc
        finally:
            self._close_pcap_writer()
            logger.info("Capture ended — %d packets total.", self._packet_count)

    def stop(self) -> None:
        """
        Signal the capture loop to exit after the next packet arrives.

        Safe to call from any thread.
        """
        self._stop_event.set()

    # ── PCAP helpers ───────────────────────────────────────────────────────────

    def _open_pcap_writer(self, path: str) -> None:
        try:
            from scapy.utils import PcapWriter

            out = Path(path)
            out.parent.mkdir(parents=True, exist_ok=True)
            self._pcap_writer = PcapWriter(str(out), append=False, sync=True)
            logger.info("PCAP output: %s", out)
        except Exception as exc:
            logger.warning("Cannot open PCAP writer for '%s': %s", path, exc)
            self._pcap_writer = None

    def _close_pcap_writer(self) -> None:
        if self._pcap_writer is not None:
            try:
                self._pcap_writer.close()
            except Exception as exc:
                logger.debug("PCAP writer close error: %s", exc)
            finally:
                self._pcap_writer = None
