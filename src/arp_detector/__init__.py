"""
ARP spoofing detection module — public API.

Exports
───────
    ARPMonitor       — top-level coordinator for one arp-watch session
    ARPTable         — MAC/IP binding store
    ARPEntry         — a single binding record
    SpoofingDetector — anomaly detection logic
    ARPEvent         — immutable anomaly event record
    ARPEventType     — event type enum
    EventLogger      — in-memory event log
    ARPAlertManager  — Rich-formatted alert output
    get_system_arp_cache — read the OS ARP cache
"""
from src.arp_detector.alerts import ARPAlertManager
from src.arp_detector.detector import SpoofingDetector
from src.arp_detector.events import ARPEvent, ARPEventType, EventLogger
from src.arp_detector.monitor import ARPMonitor
from src.arp_detector.table import ARPEntry, ARPTable, get_system_arp_cache

__all__ = [
    "ARPMonitor",
    "ARPTable",
    "ARPEntry",
    "SpoofingDetector",
    "ARPEvent",
    "ARPEventType",
    "EventLogger",
    "ARPAlertManager",
    "get_system_arp_cache",
]
