"""
Unit tests for the ARP spoofing detection module (Phase 4).

All tests use hand-crafted mock ARP packets — no live network capture or
root privileges are required.

Mock ARP packet
───────────────
Scapy's ARP layer exposes op/hwsrc/psrc/hwdst/pdst attributes.
We use a simple namespace to replicate these without importing or
constructing real Scapy packets (so tests run at full speed without
requiring scapy's C extension path for raw sockets).
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

from src.arp_detector.alerts import ARPAlertManager
from src.arp_detector.detector import SpoofingDetector
from src.arp_detector.events import ARPEvent, ARPEventType, EventLogger
from src.arp_detector.table import ARPTable


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _arp(
    op: int = 2,
    psrc: str = "192.168.1.100",
    hwsrc: str = "aa:bb:cc:dd:ee:ff",
    pdst: str = "192.168.1.1",
    hwdst: str = "00:00:00:00:00:00",
) -> SimpleNamespace:
    """Return a mock object that looks like a Scapy ARP layer."""
    return SimpleNamespace(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)


def _event(
    event_type: ARPEventType = ARPEventType.MAC_CHANGE,
    src_ip: str = "10.0.0.1",
    src_mac: str = "aa:bb:cc:dd:ee:ff",
    dst_ip: str = "10.0.0.2",
    severity: str = "high",
    description: str = "test event",
    old_mac: Optional[str] = None,
) -> ARPEvent:
    return ARPEvent(
        event_type=event_type,
        src_ip=src_ip,
        src_mac=src_mac,
        dst_ip=dst_ip,
        timestamp=datetime.now(),
        severity=severity,
        description=description,
        old_mac=old_mac,
    )


# ──────────────────────────────────────────────────────────────────────────────
# ARPTable
# ──────────────────────────────────────────────────────────────────────────────

class TestARPTable:
    def test_new_entry_returns_none(self) -> None:
        table = ARPTable()
        result = table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        assert result is None

    def test_same_mac_update_returns_none(self) -> None:
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        result = table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        assert result is None

    def test_mac_change_returns_old_mac(self) -> None:
        table = ARPTable()
        table.update("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        old = table.update("192.168.1.1", "11:22:33:44:55:66")
        assert old == "aa:bb:cc:dd:ee:ff"

    def test_known_mac_returns_current_mac(self) -> None:
        table = ARPTable()
        table.update("10.0.0.1", "de:ad:be:ef:00:01")
        assert table.known_mac("10.0.0.1") == "de:ad:be:ef:00:01"

    def test_known_mac_unknown_ip_returns_none(self) -> None:
        table = ARPTable()
        assert table.known_mac("1.2.3.4") is None

    def test_get_returns_entry(self) -> None:
        table = ARPTable()
        table.update("10.0.0.2", "ff:ee:dd:cc:bb:aa")
        entry = table.get("10.0.0.2")
        assert entry is not None
        assert entry.ip == "10.0.0.2"
        assert entry.mac == "ff:ee:dd:cc:bb:aa"
        assert entry.packet_count == 1

    def test_packet_count_increments_on_repeated_updates(self) -> None:
        table = ARPTable()
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        table.update("10.0.0.1", "aa:aa:aa:aa:aa:aa")
        assert table.get("10.0.0.1").packet_count == 3

    def test_trusted_ip_mac_change_returns_none(self) -> None:
        table = ARPTable(trusted_ips=["192.168.1.1"])
        table.update("192.168.1.1", "aa:aa:aa:aa:aa:aa")
        old = table.update("192.168.1.1", "bb:bb:bb:bb:bb:bb")
        assert old is None

    def test_trusted_ip_is_still_recorded(self) -> None:
        table = ARPTable(trusted_ips=["192.168.1.1"])
        table.update("192.168.1.1", "aa:aa:aa:aa:aa:aa")
        entry = table.get("192.168.1.1")
        assert entry is not None
        assert entry.is_trusted is True

    def test_is_trusted_true_for_listed_ip(self) -> None:
        table = ARPTable(trusted_ips=["10.0.0.1"])
        assert table.is_trusted("10.0.0.1") is True

    def test_is_trusted_false_for_unlisted_ip(self) -> None:
        table = ARPTable(trusted_ips=["10.0.0.1"])
        assert table.is_trusted("10.0.0.2") is False

    def test_all_entries_sorted_by_ip(self) -> None:
        table = ARPTable()
        table.update("192.168.1.10", "aa:aa:aa:aa:aa:01")
        table.update("192.168.1.2", "aa:aa:aa:aa:aa:02")
        table.update("192.168.1.5", "aa:aa:aa:aa:aa:03")
        ips = [e.ip for e in table.all_entries()]
        assert ips == sorted(ips)

    def test_load_from_system_returns_count(self) -> None:
        table = ARPTable()
        with patch(
            "src.arp_detector.table.get_system_arp_cache",
            return_value={"192.168.1.1": "aa:bb:cc:dd:ee:ff"},
        ):
            count = table.load_from_system()
        assert count == 1
        assert table.known_mac("192.168.1.1") == "aa:bb:cc:dd:ee:ff"

    def test_load_from_system_empty_on_error(self) -> None:
        table = ARPTable()
        with patch(
            "src.arp_detector.table.get_system_arp_cache",
            return_value={},
        ):
            count = table.load_from_system()
        assert count == 0


# ──────────────────────────────────────────────────────────────────────────────
# ARPEvent + EventLogger
# ──────────────────────────────────────────────────────────────────────────────

class TestARPEvent:
    def test_severity_level_maps_correctly(self) -> None:
        assert _event(severity="low").severity_level() == 0
        assert _event(severity="medium").severity_level() == 1
        assert _event(severity="high").severity_level() == 2
        assert _event(severity="critical").severity_level() == 3

    def test_unknown_severity_level_returns_zero(self) -> None:
        assert _event(severity="bogus").severity_level() == 0


class TestEventLogger:
    def test_starts_empty(self) -> None:
        log = EventLogger()
        assert log.total == 0
        assert log.events == []

    def test_log_appends_event(self) -> None:
        log = EventLogger()
        log.log(_event())
        assert log.total == 1

    def test_count_by_type(self) -> None:
        log = EventLogger()
        log.log(_event(event_type=ARPEventType.MAC_CHANGE))
        log.log(_event(event_type=ARPEventType.MAC_CHANGE))
        log.log(_event(event_type=ARPEventType.GRATUITOUS_ARP))
        assert log.count_by_type(ARPEventType.MAC_CHANGE) == 2
        assert log.count_by_type(ARPEventType.GRATUITOUS_ARP) == 1

    def test_count_by_severity(self) -> None:
        log = EventLogger()
        log.log(_event(severity="high"))
        log.log(_event(severity="critical"))
        log.log(_event(severity="medium"))
        assert log.count_by_severity("high") == 1
        assert log.count_by_severity("critical") == 1

    def test_high_priority_events_filters_correctly(self) -> None:
        log = EventLogger()
        log.log(_event(severity="low"))
        log.log(_event(severity="medium"))
        log.log(_event(severity="high"))
        log.log(_event(severity="critical"))
        hp = log.high_priority_events()
        assert len(hp) == 2
        assert all(e.severity in ("high", "critical") for e in hp)

    def test_events_returns_snapshot_not_live_list(self) -> None:
        log = EventLogger()
        snapshot = log.events
        log.log(_event())
        assert len(snapshot) == 0  # snapshot taken before the log call


# ──────────────────────────────────────────────────────────────────────────────
# SpoofingDetector
# ──────────────────────────────────────────────────────────────────────────────

class TestSpoofingDetector:
    def _detector(self, gateway: Optional[str] = None) -> SpoofingDetector:
        table = ARPTable()
        return SpoofingDetector(table=table, gateway_ip=gateway)

    def test_new_ip_produces_no_events(self) -> None:
        det = self._detector()
        events = det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01"))
        assert events == []

    def test_same_mac_update_produces_no_events(self) -> None:
        det = self._detector()
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01"))
        events = det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01"))
        assert events == []

    def test_mac_change_raises_high_severity_event(self) -> None:
        det = self._detector()
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01"))
        events = det.analyze(_arp(psrc="10.0.0.1", hwsrc="ff:ff:ff:ff:ff:01"))
        mac_change = [e for e in events if e.event_type == ARPEventType.MAC_CHANGE]
        assert len(mac_change) == 1
        assert mac_change[0].severity == "high"
        assert mac_change[0].old_mac == "aa:bb:cc:dd:ee:01"

    def test_gateway_mac_change_raises_critical_event(self) -> None:
        det = self._detector(gateway="192.168.1.1")
        det.analyze(_arp(psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"))
        events = det.analyze(_arp(psrc="192.168.1.1", hwsrc="ff:ff:ff:ff:ff:01"))
        gw_events = [e for e in events if e.event_type == ARPEventType.GATEWAY_MAC_CHANGE]
        assert len(gw_events) == 1
        assert gw_events[0].severity == "critical"

    def test_gratuitous_arp_detected_when_psrc_equals_pdst(self) -> None:
        det = self._detector()
        arp = _arp(op=2, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:05", pdst="10.0.0.5")
        events = det.analyze(arp)
        grat = [e for e in events if e.event_type == ARPEventType.GRATUITOUS_ARP]
        assert len(grat) == 1
        assert grat[0].severity == "medium"

    def test_gratuitous_arp_not_triggered_for_op1(self) -> None:
        det = self._detector()
        arp = _arp(op=1, psrc="10.0.0.5", hwsrc="aa:bb:cc:dd:ee:05", pdst="10.0.0.5")
        events = det.analyze(arp)
        grat = [e for e in events if e.event_type == ARPEventType.GRATUITOUS_ARP]
        assert len(grat) == 0

    def test_mitm_suspected_after_mac_change_and_gratuitous_arp(self) -> None:
        det = self._detector()
        # Establish a binding
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="10.0.0.2"))
        # Trigger a MAC change
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="ff:ff:ff:ff:ff:01", pdst="10.0.0.2"))
        # Trigger a gratuitous ARP from the same sender
        all_events = det.analyze(
            _arp(op=2, psrc="10.0.0.1", hwsrc="ff:ff:ff:ff:ff:01", pdst="10.0.0.1")
        )
        mitm = [e for e in all_events if e.event_type == ARPEventType.MITM_SUSPECTED]
        assert len(mitm) == 1
        assert mitm[0].severity == "critical"

    def test_mitm_alert_fires_only_once_per_sender(self) -> None:
        det = self._detector()
        # Establish binding + MAC change
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:01", pdst="10.0.0.2"))
        det.analyze(_arp(psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:01", pdst="10.0.0.2"))

        all_mitm = []
        # Multiple gratuitous ARP packets from the same sender
        for _ in range(5):
            events = det.analyze(
                _arp(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:01", pdst="10.0.0.1")
            )
            all_mitm.extend(e for e in events if e.event_type == ARPEventType.MITM_SUSPECTED)

        assert len(all_mitm) == 1

    def test_trusted_ip_skips_all_detection(self) -> None:
        table = ARPTable(trusted_ips=["192.168.1.1"])
        det = SpoofingDetector(table=table, gateway_ip="192.168.1.1")
        # Establish a binding
        det.analyze(_arp(psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:01"))
        # Trigger MAC change for trusted IP
        events = det.analyze(_arp(psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:01"))
        assert events == []


# ──────────────────────────────────────────────────────────────────────────────
# ARPAlertManager
# ──────────────────────────────────────────────────────────────────────────────

class TestARPAlertManager:
    def test_starts_with_zero_counts(self) -> None:
        mgr = ARPAlertManager()
        assert mgr.total_alerts == 0
        assert mgr.critical_alerts == 0

    def test_show_alert_increments_total(self) -> None:
        import src.arp_detector.alerts as _alerts_mod

        orig = _alerts_mod._stderr
        _alerts_mod._stderr = MagicMock()
        try:
            mgr = ARPAlertManager()
            mgr.show_alert(_event(severity="high"))
            assert mgr.total_alerts == 1
            assert mgr.critical_alerts == 0

            mgr.show_alert(_event(severity="critical"))
            assert mgr.total_alerts == 2
            assert mgr.critical_alerts == 1
        finally:
            _alerts_mod._stderr = orig

    def test_non_critical_alert_does_not_increment_critical_count(self) -> None:
        import src.arp_detector.alerts as _alerts_mod

        orig = _alerts_mod._stderr
        _alerts_mod._stderr = MagicMock()
        try:
            mgr = ARPAlertManager()
            mgr.show_alert(_event(severity="medium"))
            assert mgr.critical_alerts == 0
        finally:
            _alerts_mod._stderr = orig
