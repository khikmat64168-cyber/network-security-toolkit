"""
DNS domain-to-IP binding tracker.

DNSTable records the IP addresses each domain has resolved to over the
current session.  It is the DNS equivalent of ARPTable: a persistent
baseline that the detector compares each new response against.

Trusted domains are recorded normally but their IP changes are silently
accepted and never returned as "old_ip", so the detector produces no
events for them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class DNSEntry:
    """Tracks one domain's resolution history within a session."""

    domain: str
    current_ip: str
    ips_seen: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    packet_count: int = 1

    def __post_init__(self) -> None:
        self.ips_seen.add(self.current_ip)


class DNSTable:
    """
    Tracks domain → IP bindings across a dns-watch session.

    Usage
    ─────
        table = DNSTable(trusted_domains=["cdn.example.com"])
        old_ip = table.update("evil.example.com", "5.5.5.5")
        # old_ip is None (first time) or the previous IP (change detected)
    """

    def __init__(self, trusted_domains: Optional[List[str]] = None) -> None:
        self._entries: Dict[str, DNSEntry] = {}
        self._trusted: Set[str] = set(trusted_domains or [])

    def is_trusted(self, domain: str) -> bool:
        return domain in self._trusted

    def update(self, domain: str, ip: str) -> Optional[str]:
        """
        Record a domain → IP mapping.

        Returns the previous IP if it changed, None if the domain is new
        or the IP is the same as the last seen value.
        Trusted domains are always updated silently (never return old_ip).
        """
        entry = self._entries.get(domain)
        if entry is None:
            self._entries[domain] = DNSEntry(domain=domain, current_ip=ip)
            return None

        entry.packet_count += 1
        entry.last_seen = datetime.now()
        entry.ips_seen.add(ip)

        if ip == entry.current_ip:
            return None

        if self.is_trusted(domain):
            entry.current_ip = ip
            return None

        old_ip = entry.current_ip
        entry.current_ip = ip
        return old_ip

    def known_ip(self, domain: str) -> Optional[str]:
        entry = self._entries.get(domain)
        return entry.current_ip if entry else None

    def known_ips(self, domain: str) -> Set[str]:
        entry = self._entries.get(domain)
        return set(entry.ips_seen) if entry else set()

    def ip_count(self, domain: str) -> int:
        entry = self._entries.get(domain)
        return len(entry.ips_seen) if entry else 0

    def all_entries(self) -> List[DNSEntry]:
        return sorted(self._entries.values(), key=lambda e: e.domain)
