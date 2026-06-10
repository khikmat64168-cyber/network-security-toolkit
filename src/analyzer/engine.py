"""
Traffic analysis engine — coordinates all analysis components.

AnalysisEngine is the single entry point for Phase 3 analysis.
The CLI passes each ParsedPacket to engine.process() and the engine
internally routes it to:
    1. TrafficStats     — always updated
    2. CredentialDetector — when detect_credentials is enabled
    3. ThreatDetector   — when alert_on_suspicious is enabled
    4. AlertManager     — prints findings to stderr

Design decisions
────────────────
* Engine holds the mutable state (stats, detectors) for one capture
  session.  Create a new instance for each `nst sniff` invocation.
* process() never raises — all exceptions are caught and logged so
  a buggy detector cannot crash the capture loop.
"""
from __future__ import annotations

from src.analyzer.alerts import AlertManager
from src.analyzer.credentials import CredentialDetector
from src.analyzer.stats import TrafficStats
from src.analyzer.threats import ThreatDetector
from src.core.config import AnalyzerConfig
from src.core.logger import get_logger
from src.sniffer.parsers.base import ParsedPacket

logger = get_logger(__name__)


class AnalysisEngine:
    """
    Coordinates all traffic analysis components for one capture session.

    Usage
    ─────
        engine = AnalysisEngine(config.analyzer)
        # inside packet callback:
        engine.process(parsed_packet)
        # after capture:
        stats = engine.stats
    """

    def __init__(self, config: AnalyzerConfig) -> None:
        self._config = config
        self._stats = TrafficStats()
        self._cred_detector = CredentialDetector()
        self._threat_detector = ThreatDetector(
            port_scan_threshold=config.suspicious_port_scan_threshold
        )
        self._alerts = AlertManager()

    # ── Public API ──────────────────────────────────────────────────────────────

    @property
    def stats(self) -> TrafficStats:
        """Live traffic statistics — safe to read at any time."""
        return self._stats

    @property
    def alerts(self) -> AlertManager:
        """Alert manager — exposes alert counts for the final summary."""
        return self._alerts

    def process(self, packet: ParsedPacket) -> None:
        """
        Run all enabled analysis components against *packet*.

        Never raises — exceptions are swallowed and logged so a single
        bad packet cannot stop the capture loop.
        """
        try:
            self._stats.update(packet)
        except Exception as exc:
            logger.debug("Stats update error: %s", exc)

        if self._config.detect_credentials:
            try:
                findings = self._cred_detector.scan(packet)
                for finding in findings:
                    self._alerts.credential_alert(finding)
            except Exception as exc:
                logger.debug("Credential scan error: %s", exc)

        if self._config.alert_on_suspicious:
            try:
                threats = self._threat_detector.analyze(packet)
                for threat in threats:
                    self._alerts.threat_alert(threat)
            except Exception as exc:
                logger.debug("Threat detection error: %s", exc)
