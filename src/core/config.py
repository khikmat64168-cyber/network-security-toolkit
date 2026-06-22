"""
Configuration management for the Network Security Toolkit.

Design decisions
────────────────
* Typed dataclasses instead of plain dicts — IDE completion, mypy
  enforcement, and accidental-key-typo protection at load time.
* Two-level override chain:
    1. Hard-coded defaults in each dataclass (lowest priority)
    2. config/default.yaml (standard source of truth)
  Environment variables are handled in __post_init__ for the
  fields that are commonly overridden in CI / container environments.
* Unknown YAML keys are silently ignored via _build_dataclass so that
  adding new settings to config/default.yaml never breaks old code
  that hasn't been updated yet.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar

import yaml

from src.core.exceptions import ConfigurationError

T = TypeVar("T")

_PROJECT_ROOT = Path(__file__).parent.parent.parent


def _build_dataclass(cls: Type[T], data: Dict[str, Any]) -> T:
    """
    Construct a dataclass from a dict, silently ignoring unknown keys.

    This allows config/default.yaml to gain new fields without causing
    a TypeError in code that hasn't been updated to handle them yet.
    """
    valid = {f.name for f in fields(cls)}  # type: ignore[arg-type]
    filtered = {k: v for k, v in data.items() if k in valid}
    return cls(**filtered)  # type: ignore[call-arg]


# ──────────────────────────────────────────────────────────────────────────────
# Section dataclasses
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkConfig:
    """Settings that control which interface is captured and how."""

    interface: Optional[str] = None
    promiscuous: bool = True
    capture_timeout: int = 0

    def __post_init__(self) -> None:
        env_iface = os.environ.get("NST_INTERFACE")
        if env_iface and self.interface is None:
            self.interface = env_iface


@dataclass
class SnifferConfig:
    """Settings that govern the packet capture loop."""

    packet_count: int = 0
    filter: str = ""
    output_file: Optional[str] = None


@dataclass
class AnalyzerConfig:
    """Settings for the traffic analysis and alerting engine."""

    detect_credentials: bool = True
    suspicious_port_scan_threshold: int = 10
    alert_on_suspicious: bool = True


@dataclass
class ArpDetectorConfig:
    """Settings for the ARP spoofing detection module."""

    check_interval: float = 1.0
    alert_threshold: int = 3
    trusted_ips: List[str] = field(default_factory=list)
    gateway_ip: Optional[str] = None


@dataclass
class DNSDetectorConfig:
    """Settings for the DNS spoofing detection module."""

    trusted_domains: List[str] = field(default_factory=list)
    track_queries: bool = True


@dataclass
class LoggingConfig:
    """Settings that control the logging subsystem."""

    level: str = "INFO"
    file: str = "logs/network_toolkit.log"
    max_bytes: int = 10_485_760
    backup_count: int = 5

    def __post_init__(self) -> None:
        env_level = os.environ.get("NST_LOG_LEVEL")
        if env_level:
            self.level = env_level.upper()


# ──────────────────────────────────────────────────────────────────────────────
# Root config
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AppConfig:
    """
    Root application configuration.

    Aggregates all section configs.  Obtain an instance via:
        config = AppConfig.load()          # reads config/default.yaml
        config = AppConfig.from_yaml(path) # reads an explicit file
        config = AppConfig()               # uses built-in defaults only
    """

    network: NetworkConfig = field(default_factory=NetworkConfig)
    sniffer: SnifferConfig = field(default_factory=SnifferConfig)
    analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    arp_detector: ArpDetectorConfig = field(default_factory=ArpDetectorConfig)
    dns_detector: DNSDetectorConfig = field(default_factory=DNSDetectorConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: Path) -> "AppConfig":
        """
        Load configuration from *path*.

        Raises ConfigurationError if the file is missing or cannot be
        parsed as valid YAML.
        """
        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        try:
            with open(path, encoding="utf-8") as fh:
                raw: Dict[str, Any] = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Failed to parse configuration file '{path}': {exc}"
            ) from exc

        return cls(
            network=_build_dataclass(NetworkConfig, raw.get("network") or {}),
            sniffer=_build_dataclass(SnifferConfig, raw.get("sniffer") or {}),
            analyzer=_build_dataclass(AnalyzerConfig, raw.get("analyzer") or {}),
            arp_detector=_build_dataclass(
                ArpDetectorConfig, raw.get("arp_detector") or {}
            ),
            dns_detector=_build_dataclass(
                DNSDetectorConfig, raw.get("dns_detector") or {}
            ),
            logging=_build_dataclass(LoggingConfig, raw.get("logging") or {}),
        )

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "AppConfig":
        """
        Load configuration, falling back gracefully to built-in defaults.

        If *config_path* is None the method looks for
        ``<project_root>/config/default.yaml``.  If that file does not
        exist either, all dataclass defaults are used — no error is
        raised so the toolkit remains runnable without any config file.
        """
        if config_path is None:
            config_path = _PROJECT_ROOT / "config" / "default.yaml"

        if config_path.exists():
            return cls.from_yaml(config_path)

        return cls()
