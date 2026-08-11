"""
Data models for the HTML report generator.

All models are plain frozen / regular dataclasses — no I/O, no Rich,
no Scapy.  The builder converts live toolkit objects into these models;
the renderer converts them into HTML.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from src.geoip.models import GeoResult


@dataclass
class TLSFinding:
    """One host's TLS scan result, simplified for the report."""

    host: str
    port: int
    tls_version: str
    cipher_suite: str
    subject: str
    issuer: str
    days_until_expiry: Optional[int]        # None when scan failed
    issues: List[str]                       # human-readable issue strings
    severity: str                           # "ok"|"warning"|"high"|"critical"|"error"
    geo: Optional[GeoResult] = None         # populated by ReportBuilder.add_geo()

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class InterfaceInfo:
    """One network interface snapshot."""

    name: str
    ip: Optional[str]
    mac: Optional[str]
    is_default: bool = False


@dataclass
class ReportData:
    """
    Root data bag for one NST report session.

    Populated by ReportBuilder, consumed by the HTML renderer.
    """

    generated_at: datetime
    toolkit_version: str = "1.0.0"
    hostname: str = field(default_factory=socket.gethostname)

    tls_findings: List[TLSFinding] = field(default_factory=list)
    interfaces: List[InterfaceInfo] = field(default_factory=list)

    # ── Computed summaries ──────────────────────────────────────────

    @property
    def total_tls_issues(self) -> int:
        return sum(len(f.issues) for f in self.tls_findings)

    @property
    def critical_tls_count(self) -> int:
        return sum(1 for f in self.tls_findings if f.severity == "critical")

    @property
    def high_tls_count(self) -> int:
        return sum(1 for f in self.tls_findings if f.severity == "high")

    @property
    def ok_tls_count(self) -> int:
        return sum(1 for f in self.tls_findings if f.severity == "ok")

    @property
    def warning_tls_count(self) -> int:
        return sum(1 for f in self.tls_findings if f.severity == "warning")
