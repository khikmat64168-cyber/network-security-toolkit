"""
Result types for the TLS certificate inspector.

IssueType  — str-enum of every vulnerability class we detect.
CertIssue  — one detected problem with severity and human detail.
TLSScanResult — full scan output for one host:port.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class IssueType(str, Enum):
    EXPIRED          = "expired"
    EXPIRING_SOON    = "expiring_soon"
    SELF_SIGNED      = "self_signed"
    WEAK_TLS_VERSION = "weak_tls_version"
    WEAK_CIPHER      = "weak_cipher"
    WEAK_KEY_SIZE    = "weak_key_size"
    HOSTNAME_MISMATCH = "hostname_mismatch"


@dataclass
class CertIssue:
    """One detected certificate problem."""

    issue_type: IssueType
    severity: str    # "medium" | "high" | "critical"
    detail: str

    def severity_level(self) -> int:
        return {"medium": 1, "high": 2, "critical": 3}.get(self.severity, 0)


@dataclass
class TLSScanResult:
    """Complete TLS scan output for one host:port."""

    host: str
    port: int
    tls_version: str
    cipher_suite: str
    key_bits: int

    # Certificate fields
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san: List[str]                            # Subject Alternative Names (DNS)

    # Analysis
    issues: List[CertIssue] = field(default_factory=list)
    error: Optional[str] = None              # set when connection/parse failed

    @property
    def is_ok(self) -> bool:
        return not self.issues and self.error is None

    @property
    def days_until_expiry(self) -> int:
        return (self.not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "high")
