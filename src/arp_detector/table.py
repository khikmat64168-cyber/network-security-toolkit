"""
ARP binding table — ground truth for MAC/IP verification.

Design decisions
────────────────
* ARPEntry tracks first_seen and last_seen so the CLI can show how
  long a binding has been stable — a very new entry that immediately
  conflicts is more suspicious than one that has been stable for minutes.
* load_from_system() pre-populates the table from the OS ARP cache at
  startup so we detect changes from the known-good baseline, not just
  changes that happen to occur within the capture window.
* Trusted IPs are marked at insert time — update() still records them
  but returns None (no conflict), so the detector never raises alerts
  for hosts the user has explicitly whitelisted.
* get_system_arp_cache() is intentionally a module-level function
  (not a method) so it can be tested and called independently.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class ARPEntry:
    """A single verified MAC/IP binding."""

    ip: str
    mac: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 1
    is_trusted: bool = False

    def age_seconds(self) -> float:
        return (datetime.now() - self.first_seen).total_seconds()


class ARPTable:
    """
    Maintains a MAC/IP binding table built from observed ARP traffic.

    Usage
    ─────
        table = ARPTable(trusted_ips=["192.168.1.1"])
        table.load_from_system()       # optional: seed from OS cache
        old_mac = table.update(ip, mac)
        if old_mac:
            print(f"MAC changed for {ip}: {old_mac} → {mac}")
    """

    def __init__(self, trusted_ips: Optional[List[str]] = None) -> None:
        self._entries: Dict[str, ARPEntry] = {}
        self._trusted: Set[str] = set(trusted_ips or [])

    # ── Mutation ───────────────────────────────────────────────────────────────

    def update(self, ip: str, mac: str) -> Optional[str]:
        """
        Record an IP→MAC binding.

        Returns the *previous* MAC if it has changed (possible spoofing),
        or None if the binding is new or unchanged.
        Trusted IPs always return None regardless of MAC changes.
        """
        if ip in self._trusted:
            # Still record the entry so the table is complete
            entry = self._entries.get(ip)
            if entry:
                entry.last_seen = datetime.now()
                entry.packet_count += 1
            else:
                self._entries[ip] = ARPEntry(
                    ip=ip,
                    mac=mac,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    is_trusted=True,
                )
            return None

        entry = self._entries.get(ip)
        if entry is None:
            self._entries[ip] = ARPEntry(
                ip=ip,
                mac=mac,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                is_trusted=False,
            )
            return None

        entry.last_seen = datetime.now()
        entry.packet_count += 1

        if entry.mac != mac:
            old_mac = entry.mac
            entry.mac = mac
            return old_mac

        return None

    # ── Read ───────────────────────────────────────────────────────────────────

    def get(self, ip: str) -> Optional[ARPEntry]:
        """Return the entry for *ip*, or None if unknown."""
        return self._entries.get(ip)

    def all_entries(self) -> List[ARPEntry]:
        """Return all entries sorted by IP address."""
        return sorted(self._entries.values(), key=lambda e: e.ip)

    def is_trusted(self, ip: str) -> bool:
        return ip in self._trusted

    def known_mac(self, ip: str) -> Optional[str]:
        entry = self._entries.get(ip)
        return entry.mac if entry else None

    # ── System cache ───────────────────────────────────────────────────────────

    def load_from_system(self) -> int:
        """
        Pre-populate this table from the OS ARP cache.

        Returns the number of entries imported.  Silently ignores errors
        so a failed cache read never prevents the monitor from starting.
        """
        cache = get_system_arp_cache()
        for ip, mac in cache.items():
            self.update(ip, mac)
        return len(cache)


# ──────────────────────────────────────────────────────────────────────────────
# OS ARP cache reader
# ──────────────────────────────────────────────────────────────────────────────

def get_system_arp_cache() -> Dict[str, str]:
    """
    Return the OS ARP cache as {ip: mac}.

    Supports macOS (arp -a) and Linux (/proc/net/arp).
    Returns an empty dict on any error.
    """
    import platform

    system = platform.system()
    try:
        if system == "Darwin":
            return _read_macos_arp()
        if system == "Linux":
            return _read_linux_arp()
    except Exception:
        pass
    return {}


def _read_macos_arp() -> Dict[str, str]:
    output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
    result: Dict[str, str] = {}
    # Example line: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    pattern = re.compile(r"\(([0-9.]+)\)\s+at\s+([0-9a-f:]{17})", re.IGNORECASE)
    for match in pattern.finditer(output):
        result[match.group(1)] = match.group(2).lower()
    return result


def _read_linux_arp() -> Dict[str, str]:
    result: Dict[str, str] = {}
    with open("/proc/net/arp", encoding="utf-8") as fh:
        next(fh)  # skip header row
        for line in fh:
            parts = line.split()
            if len(parts) >= 4:
                ip, _hw_type, _flags, mac = parts[:4]
                if mac != "00:00:00:00:00:00":
                    result[ip] = mac.lower()
    return result
