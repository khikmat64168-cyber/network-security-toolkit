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
from src.analyzer.alerts import AlertManager
from src.analyzer.credentials import CredentialDetector, CredentialFinding
from src.analyzer.engine import AnalysisEngine
from src.analyzer.stats import TrafficStats
from src.analyzer.threats import ThreatDetector, ThreatEvent

__all__ = [
    "AnalysisEngine",
    "TrafficStats",
    "CredentialDetector",
    "CredentialFinding",
    "ThreatDetector",
    "ThreatEvent",
    "AlertManager",
]
