"""
Tests for Phase 9 — MAC Flooding Detector.

Coverage
────────
* MACEntry / MACTable              (table.py)
* MACEventType / MACEvent          (events.py)
* EventLogger                      (events.py)
* FloodDetector                    (detector.py)
* MACAlertManager                  (alerts.py)
* MACMonitor                       (monitor.py)
* mac-watch CLI smoke              (cli/main.py)
"""
from __future__ import annotations

import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nst.core.config import MACDetectorConfig, NetworkConfig
from nst.core.exceptions import CaptureError, InsufficientPermissionsError
from nst.mac_detector.alerts import MACAlertManager
from nst.mac_detector.detector import FloodDetector, _FLOOD_COOLDOWN
from nst.mac_detector.events import EventLogger, MACEvent, MACEventType
from nst.mac_detector.monitor import MACMonitor
from nst.mac_detector.table import MACEntry, MACTable, _is_broadcast_or_multicast


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _event(
    event_type: MACEventType = MACEventType.FLOOD_DETECTED,
    mac: str = "aa:bb:cc:dd:ee:ff",
    new_macs: int = 55,
    total: int = 100,
    severity: str = "high",
    description: str = "test",
) -> MACEvent:
    return MACEvent(
        event_type=event_type,
        mac=mac,
        new_macs_in_window=new_macs,
        total_macs=total,
        timestamp=datetime.now(),
        severity=severity,
        description=description,
    )


def _unique_mac(n: int) -> str:
    """Generate a unicast MAC address from an integer."""
    b = n.to_bytes(6, "big")
    hex_bytes = [f"{x:02x}" for x in b]
    hex_bytes[0] = f"{(int(hex_bytes[0], 16) & 0xFE):02x}"  # clear multicast bit
    return ":".join(hex_bytes)


# ──────────────────────────────────────────────────────────────────────────────
# _is_broadcast_or_multicast
# ──────────────────────────────────────────────────────────────────────────────

class TestBroadcastMulticastFilter:
    def test_broadcast_detected(self):
        assert _is_broadcast_or_multicast("ff:ff:ff:ff:ff:ff") is True

    def test_broadcast_uppercase(self):
        assert _is_broadcast_or_multicast("FF:FF:FF:FF:FF:FF") is True

    def test_multicast_01_prefix(self):
        assert _is_broadcast_or_multicast("01:00:5e:00:00:01") is True

    def test_multicast_odd_first_byte(self):
        assert _is_broadcast_or_multicast("03:00:00:00:00:01") is True

    def test_unicast_not_filtered(self):
        assert _is_broadcast_or_multicast("aa:bb:cc:dd:ee:ff") is False

    def test_unicast_00_prefix(self):
        assert _is_broadcast_or_multicast("00:11:22:33:44:55") is False

    def test_invalid_mac_returns_false(self):
        assert _is_broadcast_or_multicast("not-a-mac") is False


# ──────────────────────────────────────────────────────────────────────────────
# MACTable
# ──────────────────────────────────────────────────────────────────────────────

class TestMACTable:
    def test_new_mac_returns_true(self):
        table = MACTable()
        assert table.add("aa:bb:cc:dd:ee:01", 1.0) is True

    def test_duplicate_mac_returns_false(self):
        table = MACTable()
        table.add("aa:bb:cc:dd:ee:01", 1.0)
        assert table.add("aa:bb:cc:dd:ee:01", 2.0) is False

    def test_broadcast_silently_ignored(self):
        table = MACTable()
        result = table.add("ff:ff:ff:ff:ff:ff", 1.0)
        assert result is False
        assert table.total() == 0

    def test_multicast_silently_ignored(self):
        table = MACTable()
        result = table.add("01:00:5e:00:00:01", 1.0)
        assert result is False
        assert table.total() == 0

    def test_total_counts_unique_macs(self):
        table = MACTable()
        for i in range(5):
            table.add(_unique_mac(i), float(i))
        assert table.total() == 5

    def test_packet_count_increments_on_duplicate(self):
        table = MACTable()
        table.add("aa:bb:cc:dd:ee:01", 1.0)
        table.add("aa:bb:cc:dd:ee:01", 2.0)
        entry = table.all_entries()[0]
        assert entry.packet_count == 2

    def test_new_in_window_counts_recent(self):
        table = MACTable()
        now = 100.0
        table.add(_unique_mac(1), now - 1.0)   # within 5s window
        table.add(_unique_mac(2), now - 4.9)   # within 5s window
        table.add(_unique_mac(3), now - 6.0)   # outside window
        assert table.new_in_window(5.0, now) == 2

    def test_new_in_window_all_outside_returns_zero(self):
        table = MACTable()
        now = 100.0
        table.add(_unique_mac(1), now - 10.0)
        assert table.new_in_window(5.0, now) == 0

    def test_all_entries_sorted_by_first_seen(self):
        table = MACTable()
        table.add(_unique_mac(3), 3.0)
        table.add(_unique_mac(1), 1.0)
        table.add(_unique_mac(2), 2.0)
        entries = table.all_entries()
        assert [e.first_seen for e in entries] == [1.0, 2.0, 3.0]


# ──────────────────────────────────────────────────────────────────────────────
# MACEvent / EventLogger
# ──────────────────────────────────────────────────────────────────────────────

class TestMACEvent:
    def test_severity_level_high(self):
        e = _event(severity="high")
        assert e.severity_level() == 2

    def test_severity_level_critical(self):
        e = _event(severity="critical")
        assert e.severity_level() == 3

    def test_severity_level_unknown_returns_zero(self):
        e = _event(severity="unknown_level")
        assert e.severity_level() == 0


class TestEventLogger:
    def test_total_zero_initially(self):
        logger = EventLogger()
        assert logger.total == 0

    def test_log_increments_total(self):
        logger = EventLogger()
        logger.log(_event())
        assert logger.total == 1

    def test_count_by_type(self):
        logger = EventLogger()
        logger.log(_event(MACEventType.FLOOD_DETECTED))
        logger.log(_event(MACEventType.FLOOD_DETECTED))
        logger.log(_event(MACEventType.TABLE_OVERFLOW, severity="critical"))
        assert logger.count_by_type(MACEventType.FLOOD_DETECTED) == 2
        assert logger.count_by_type(MACEventType.TABLE_OVERFLOW) == 1

    def test_high_priority_events(self):
        logger = EventLogger()
        logger.log(_event(severity="high"))
        logger.log(_event(severity="critical"))
        assert len(logger.high_priority_events()) == 2

    def test_events_returns_copy(self):
        logger = EventLogger()
        logger.log(_event())
        first = logger.events
        logger.log(_event())
        assert len(first) == 1   # original list not mutated


# ──────────────────────────────────────────────────────────────────────────────
# FloodDetector
# ──────────────────────────────────────────────────────────────────────────────

class TestFloodDetector:
    def _make(self, threshold=5, window=5.0, limit=100):
        table = MACTable()
        return FloodDetector(table, threshold=threshold,
                             window_secs=window, table_limit=limit)

    def test_no_events_for_known_mac(self):
        det = self._make()
        det._table.add("aa:bb:cc:dd:ee:01", 1.0)
        events = det.analyze("aa:bb:cc:dd:ee:01", 2.0)
        assert events == []

    def test_no_event_below_threshold(self):
        det = self._make(threshold=10)
        now = 100.0
        for i in range(4):
            events = det.analyze(_unique_mac(i), now + i * 0.1)
        assert all(len(det.analyze(_unique_mac(i), now)) == 0 for i in range(5, 9))

    def test_flood_event_at_threshold(self):
        det = self._make(threshold=5, window=10.0)
        now = 100.0
        all_events = []
        for i in range(5):
            all_events.extend(det.analyze(_unique_mac(i), now + i * 0.1))
        flood_events = [e for e in all_events if e.event_type == MACEventType.FLOOD_DETECTED]
        assert len(flood_events) == 1

    def test_flood_event_severity_is_high(self):
        det = self._make(threshold=3, window=10.0)
        now = 100.0
        events = []
        for i in range(3):
            events.extend(det.analyze(_unique_mac(i), now + i * 0.1))
        flood = [e for e in events if e.event_type == MACEventType.FLOOD_DETECTED]
        assert flood[0].severity == "high"

    def test_flood_cooldown_suppresses_repeat_alert(self):
        det = self._make(threshold=3, window=60.0)
        now = 100.0
        all_events = []
        for i in range(20):
            all_events.extend(det.analyze(_unique_mac(i), now + i * 0.1))
        flood_events = [e for e in all_events if e.event_type == MACEventType.FLOOD_DETECTED]
        assert len(flood_events) == 1

    def test_flood_cooldown_allows_alert_after_expiry(self):
        # Use a short window (2s) so we can place the second burst outside it.
        det = self._make(threshold=3, window=2.0)
        now = 100.0
        # First burst — fills window, triggers alert
        for i in range(3):
            det.analyze(_unique_mac(i), now + i * 0.1)
        # Advance past both the cooldown AND the window so the second burst
        # stands alone in its own 2-second window.
        later = now + _FLOOD_COOLDOWN + 5.0
        all_events = []
        for i in range(3, 6):
            all_events.extend(det.analyze(_unique_mac(i), later + i * 0.1))
        assert any(e.event_type == MACEventType.FLOOD_DETECTED for e in all_events)

    def test_table_overflow_event(self):
        det = self._make(threshold=1000, limit=5)
        now = 100.0
        all_events = []
        for i in range(5):
            all_events.extend(det.analyze(_unique_mac(i), now + i))
        overflow = [e for e in all_events if e.event_type == MACEventType.TABLE_OVERFLOW]
        assert len(overflow) == 1

    def test_table_overflow_severity_is_critical(self):
        det = self._make(threshold=1000, limit=3)
        now = 100.0
        all_events = []
        for i in range(3):
            all_events.extend(det.analyze(_unique_mac(i), now + i))
        overflow = [e for e in all_events if e.event_type == MACEventType.TABLE_OVERFLOW]
        assert overflow[0].severity == "critical"

    def test_overflow_fires_only_once(self):
        det = self._make(threshold=1000, limit=3)
        now = 100.0
        all_events = []
        for i in range(10):
            all_events.extend(det.analyze(_unique_mac(i), now + i))
        overflow = [e for e in all_events if e.event_type == MACEventType.TABLE_OVERFLOW]
        assert len(overflow) == 1

    def test_broadcast_mac_returns_no_events(self):
        det = self._make(threshold=1)
        events = det.analyze("ff:ff:ff:ff:ff:ff", 1.0)
        assert events == []


# ──────────────────────────────────────────────────────────────────────────────
# MACAlertManager
# ──────────────────────────────────────────────────────────────────────────────

class TestMACAlertManager:
    def test_initial_counts_zero(self):
        mgr = MACAlertManager()
        assert mgr.total_alerts == 0
        assert mgr.critical_alerts == 0

    def test_show_alert_increments_total(self):
        mgr = MACAlertManager()
        with patch("nst.mac_detector.alerts._stderr"):
            mgr.show_alert(_event(severity="high"))
        assert mgr.total_alerts == 1

    def test_critical_alert_increments_critical_count(self):
        mgr = MACAlertManager()
        with patch("nst.mac_detector.alerts._stderr"):
            mgr.show_alert(_event(severity="critical"))
        assert mgr.critical_alerts == 1

    def test_high_alert_does_not_increment_critical(self):
        mgr = MACAlertManager()
        with patch("nst.mac_detector.alerts._stderr"):
            mgr.show_alert(_event(severity="high"))
        assert mgr.critical_alerts == 0


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMACMonitor:
    @staticmethod
    def _monitor(threshold: int = 3) -> MACMonitor:
        return MACMonitor(
            MACDetectorConfig(flood_threshold=threshold, window_secs=60.0, table_limit=1000),
            NetworkConfig(interface="lo0"),
        )

    @staticmethod
    def _frame(mac: str):
        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether

        return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP()

    def test_counts_every_packet(self) -> None:
        from scapy.layers.inet import IP

        monitor = self._monitor()
        monitor._on_packet(self._frame("02:00:00:00:00:01"))
        monitor._on_packet(IP())                       # no Ethernet layer
        assert monitor.packet_count == 2
        assert monitor.table.total() == 1

    def test_flood_raises_event_and_alert(self) -> None:
        monitor = self._monitor(threshold=3)
        with patch.object(monitor.alert_manager, "show_alert") as show:
            for i in range(5):
                monitor._on_packet(self._frame(f"02:00:00:00:00:{i:02x}"))
        assert monitor.event_logger.count_by_type(MACEventType.FLOOD_DETECTED) >= 1
        assert show.called

    def test_detector_errors_are_contained(self) -> None:
        monitor = self._monitor()
        with patch.object(monitor.detector, "analyze", side_effect=ValueError("bad")):
            monitor._on_packet(self._frame("02:00:00:00:00:01"))
        assert monitor.event_logger.count_by_type(MACEventType.FLOOD_DETECTED) == 0

    def test_start_passes_interface_and_stop_filter(self) -> None:
        monitor = self._monitor()
        with patch("scapy.sendrecv.sniff") as sniff:
            monitor.start()
        kwargs = sniff.call_args.kwargs
        assert kwargs["iface"] == "lo0"
        assert kwargs["store"] is False
        assert kwargs["stop_filter"](None) is False
        monitor.stop()
        assert kwargs["stop_filter"](None) is True

    def test_permission_error_is_translated(self) -> None:
        monitor = self._monitor()
        with patch("scapy.sendrecv.sniff", side_effect=PermissionError("denied")):
            with pytest.raises(InsufficientPermissionsError):
                monitor.start()

    def test_os_error_is_translated(self) -> None:
        monitor = self._monitor()
        with patch("scapy.sendrecv.sniff", side_effect=OSError("iface down")):
            with pytest.raises(CaptureError):
                monitor.start()


class TestMACWatchCLI:
    def test_mac_watch_requires_root(self):
        from nst.cli.main import cli

        runner = CliRunner()
        with patch("os.geteuid", return_value=1000):
            result = runner.invoke(cli, ["mac-watch"])
        assert result.exit_code == 1

    def test_mac_watch_runs_and_exits_cleanly(self):
        from nst.cli.main import cli

        mock_monitor = MagicMock()
        mock_monitor.packet_count = 42
        mock_monitor.table.total.return_value = 10
        mock_monitor.table.all_entries.return_value = []
        mock_monitor.event_logger.count_by_type.return_value = 0
        mock_monitor.alert_manager.total_alerts = 0
        mock_monitor.alert_manager.critical_alerts = 0
        mock_monitor.start.side_effect = KeyboardInterrupt

        runner = CliRunner()
        with patch("os.geteuid", return_value=0), \
             patch("nst.mac_detector.monitor.MACMonitor", return_value=mock_monitor):
            result = runner.invoke(cli, ["mac-watch"])

        assert result.exit_code == 0

    def test_mac_watch_threshold_option_applied(self):
        from nst.cli.main import cli

        mock_monitor = MagicMock()
        mock_monitor.packet_count = 0
        mock_monitor.table.total.return_value = 0
        mock_monitor.table.all_entries.return_value = []
        mock_monitor.event_logger.count_by_type.return_value = 0
        mock_monitor.alert_manager.total_alerts = 0
        mock_monitor.alert_manager.critical_alerts = 0
        mock_monitor.start.side_effect = KeyboardInterrupt

        captured_config = {}

        def capture_init(cfg, net_cfg):
            captured_config["threshold"] = cfg.flood_threshold
            return mock_monitor

        runner = CliRunner()
        with patch("os.geteuid", return_value=0), \
             patch("nst.mac_detector.monitor.MACMonitor", side_effect=capture_init):
            runner.invoke(cli, ["mac-watch", "--threshold", "25"])

        assert captured_config.get("threshold") == 25
