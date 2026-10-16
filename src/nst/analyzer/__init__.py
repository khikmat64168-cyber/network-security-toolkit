"""
Traffic analysis module — public API.

Exports
───────
    AnalysisEngine     — main coordinator (one per capture session)
    TrafficStats       — protocol counters and top-N rankings
    CredentialDetector — plaintext credential scanner
    CredentialFinding  — detected credential data model
    ThreatDetector     — port scan / DNS tunneling / suspicious port detection
    ThreatEvent        — detected threat data model
    AlertManager       — Rich-formatted alert output
"""
from nst.analyzer.alerts import AlertManager
from nst.analyzer.credentials import CredentialDetector, CredentialFinding
from nst.analyzer.engine import AnalysisEngine
from nst.analyzer.stats import TrafficStats
from nst.analyzer.threats import ThreatDetector, ThreatEvent

__all__ = [
    "AnalysisEngine",
    "TrafficStats",
    "CredentialDetector",
    "CredentialFinding",
    "ThreatDetector",
    "ThreatEvent",
    "AlertManager",
]
