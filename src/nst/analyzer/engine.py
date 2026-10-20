"""
Traffic analysis engine — coordinates all analysis components.

AnalysisEngine is the single entry point for Phase 3 analysis.
The CLI passes each ParsedPacket to engine.process() and the engine
internally routes it to:
    1. TrafficStats     — always updated
    2. CredentialDetector — when detect_credentials is enabled
    3. ThreatDetector   — when alert_on_suspicious is enabled
    4. AlertManager     — prints findings to stderr (console_alerts=True)
    5. listener         — optional callback receiving every finding, used
                          by the web dashboard to stream events

Design decisions
────────────────
* Engine holds the mutable state (stats, detectors) for one capture
  session.  Create a new instance for each `nst sniff` invocation.
* process() never raises — all exceptions are caught and logged so
  a buggy detector cannot crash the capture loop.  The same applies to
  a misbehaving listener.
"""
from __future__ import annotations

from typing import Callable, Optional, Union

from nst.analyzer.alerts import AlertManager
from nst.analyzer.credentials import CredentialDetector, CredentialFinding
from nst.analyzer.stats import TrafficStats
from nst.analyzer.threats import ThreatDetector, ThreatEvent
from nst.core.config import AnalyzerConfig
from nst.core.logger import get_logger
from nst.sniffer.parsers.base import ParsedPacket

logger = get_logger(__name__)

Finding = Union[CredentialFinding, ThreatEvent]


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

    def __init__(
        self,
        config: AnalyzerConfig,
        listener: Optional[Callable[[Finding], None]] = None,
        console_alerts: bool = True,
    ) -> None:
        self._config = config
        self._listener = listener
        self._console_alerts = console_alerts
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
                    if self._console_alerts:
                        self._alerts.credential_alert(finding)
                    else:
                        self._alerts.credential_count += 1
                    self._notify(finding)
            except Exception as exc:
                logger.debug("Credential scan error: %s", exc)

        if self._config.alert_on_suspicious:
            try:
                threats = self._threat_detector.analyze(packet)
                for threat in threats:
                    if self._console_alerts:
                        self._alerts.threat_alert(threat)
                    else:
                        self._alerts.threat_count += 1
                    self._notify(threat)
            except Exception as exc:
                logger.debug("Threat detection error: %s", exc)

    # ── Internal ────────────────────────────────────────────────────────────────

    def _notify(self, finding: Finding) -> None:
        if self._listener is None:
            return
        try:
            self._listener(finding)
        except Exception as exc:
            logger.debug("Finding listener error: %s", exc)
