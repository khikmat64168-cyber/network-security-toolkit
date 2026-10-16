"""
Unit tests for the configuration system (src/core/config.py).

Tests cover:
  - Default values for every section dataclass
  - Loading from a valid YAML file
  - Unknown YAML keys are silently ignored
  - Missing YAML sections fall back to defaults
  - ConfigurationError is raised for a missing file
  - ConfigurationError is raised for malformed YAML
  - An empty YAML file is treated as all-defaults
  - AppConfig.load() with a missing path returns defaults
  - Environment variable overrides (NST_INTERFACE, NST_LOG_LEVEL)
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from nst.core.config import (
    AnalyzerConfig,
    AppConfig,
    ArpDetectorConfig,
    LoggingConfig,
    NetworkConfig,
    SnifferConfig,
)
from nst.core.exceptions import ConfigurationError


# ──────────────────────────────────────────────────────────────────────────────
# NetworkConfig
# ──────────────────────────────────────────────────────────────────────────────

class TestNetworkConfig:
    def test_defaults(self) -> None:
        cfg = NetworkConfig()
        assert cfg.interface is None
        assert cfg.promiscuous is True
        assert cfg.capture_timeout == 0

    def test_custom_values(self) -> None:
        cfg = NetworkConfig(interface="eth0", promiscuous=False, capture_timeout=60)
        assert cfg.interface == "eth0"
        assert cfg.promiscuous is False
        assert cfg.capture_timeout == 60

    def test_env_var_sets_interface(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NST_INTERFACE", "wlan0")
        cfg = NetworkConfig()
        assert cfg.interface == "wlan0"

    def test_env_var_does_not_override_explicit_interface(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NST_INTERFACE", "wlan0")
        cfg = NetworkConfig(interface="eth0")
        assert cfg.interface == "eth0"


# ──────────────────────────────────────────────────────────────────────────────
# LoggingConfig
# ──────────────────────────────────────────────────────────────────────────────

class TestLoggingConfig:
    def test_defaults(self) -> None:
        cfg = LoggingConfig()
        assert cfg.level == "INFO"
        assert cfg.max_bytes == 10_485_760
        assert cfg.backup_count == 5

    def test_env_var_sets_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NST_LOG_LEVEL", "debug")
        cfg = LoggingConfig()
        assert cfg.level == "DEBUG"


# ──────────────────────────────────────────────────────────────────────────────
# AppConfig — from_yaml
# ──────────────────────────────────────────────────────────────────────────────

class TestAppConfigFromYaml:
    def test_raises_for_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError, match="not found"):
            AppConfig.from_yaml(tmp_path / "nonexistent.yaml")

    def test_raises_for_invalid_yaml(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(": invalid: [\n")
        with pytest.raises(ConfigurationError, match="parse"):
            AppConfig.from_yaml(bad)

    def test_empty_file_returns_all_defaults(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        cfg = AppConfig.from_yaml(empty)
        assert isinstance(cfg, AppConfig)
        assert cfg.network.interface is None
        assert cfg.logging.level == "INFO"

    def test_partial_yaml_merges_with_defaults(self, tmp_path: Path) -> None:
        data = {"network": {"interface": "lo0"}}
        f = tmp_path / "partial.yaml"
        f.write_text(yaml.dump(data))
        cfg = AppConfig.from_yaml(f)
        assert cfg.network.interface == "lo0"
        assert cfg.network.promiscuous is True    # default preserved
        assert cfg.network.capture_timeout == 0   # default preserved

    def test_full_yaml_overrides_all_defaults(self, tmp_path: Path) -> None:
        data = {
            "network": {"interface": "eth0", "promiscuous": False, "capture_timeout": 30},
            "sniffer": {"packet_count": 100, "filter": "tcp", "output_file": "/tmp/out.pcap"},
            "analyzer": {
                "detect_credentials": False,
                "suspicious_port_scan_threshold": 5,
                "alert_on_suspicious": False,
            },
            "arp_detector": {
                "check_interval": 2.5,
                "alert_threshold": 5,
                "trusted_ips": ["10.0.0.1", "10.0.0.254"],
            },
            "logging": {"level": "DEBUG", "file": "/var/log/nst.log", "max_bytes": 1024, "backup_count": 2},
        }
        f = tmp_path / "full.yaml"
        f.write_text(yaml.dump(data))
        cfg = AppConfig.from_yaml(f)

        assert cfg.network.interface == "eth0"
        assert cfg.network.promiscuous is False
        assert cfg.network.capture_timeout == 30
        assert cfg.sniffer.packet_count == 100
        assert cfg.sniffer.filter == "tcp"
        assert cfg.sniffer.output_file == "/tmp/out.pcap"
        assert cfg.analyzer.detect_credentials is False
        assert cfg.analyzer.suspicious_port_scan_threshold == 5
        assert cfg.arp_detector.check_interval == 2.5
        assert cfg.arp_detector.trusted_ips == ["10.0.0.1", "10.0.0.254"]
        assert cfg.logging.level == "DEBUG"

    def test_unknown_yaml_keys_are_ignored(self, tmp_path: Path) -> None:
        data = {"network": {"interface": "eth0", "unknown_future_key": "value"}}
        f = tmp_path / "extra_keys.yaml"
        f.write_text(yaml.dump(data))
        cfg = AppConfig.from_yaml(f)   # must not raise TypeError
        assert cfg.network.interface == "eth0"


# ──────────────────────────────────────────────────────────────────────────────
# AppConfig — load
# ──────────────────────────────────────────────────────────────────────────────

class TestAppConfigLoad:
    def test_returns_defaults_when_file_missing(self, tmp_path: Path) -> None:
        cfg = AppConfig.load(config_path=tmp_path / "does_not_exist.yaml")
        assert isinstance(cfg, AppConfig)
        assert cfg.network.interface is None
        assert cfg.logging.level == "INFO"

    def test_loads_existing_file(self, tmp_path: Path) -> None:
        data = {"logging": {"level": "WARNING"}}
        f = tmp_path / "config.yaml"
        f.write_text(yaml.dump(data))
        cfg = AppConfig.load(config_path=f)
        assert cfg.logging.level == "WARNING"

    def test_default_path_points_to_project_config(self) -> None:
        # AppConfig.load() without arguments should not raise,
        # regardless of whether config/default.yaml exists.
        cfg = AppConfig.load()
        assert isinstance(cfg, AppConfig)


# ──────────────────────────────────────────────────────────────────────────────
# AppConfig — config file discovery
# ──────────────────────────────────────────────────────────────────────────────

class TestAppConfigDiscovery:
    def test_bundled_defaults_are_loaded(self, monkeypatch: pytest.MonkeyPatch,
                                         tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        monkeypatch.delenv("NST_CONFIG", raising=False)
        from nst.core.paths import BUNDLED_CONFIG_FILE

        bundled = yaml.safe_load(BUNDLED_CONFIG_FILE.read_text())
        cfg = AppConfig.load()
        assert cfg.mac_detector.flood_threshold == bundled["mac_detector"]["flood_threshold"]
        assert cfg.logging.file == bundled["logging"]["file"]

    def test_user_config_overrides_bundled(self, monkeypatch: pytest.MonkeyPatch,
                                           tmp_path: Path) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        monkeypatch.delenv("NST_CONFIG", raising=False)
        user_file = tmp_path / "nst" / "config.yaml"
        user_file.parent.mkdir()
        user_file.write_text("mac_detector:\n  flood_threshold: 7\n")
        assert AppConfig.load().mac_detector.flood_threshold == 7

    def test_nst_config_env_var_wins(self, monkeypatch: pytest.MonkeyPatch,
                                     tmp_path: Path) -> None:
        user_file = tmp_path / "nst" / "config.yaml"
        user_file.parent.mkdir()
        user_file.write_text("mac_detector:\n  flood_threshold: 7\n")
        env_file = tmp_path / "env.yaml"
        env_file.write_text("mac_detector:\n  flood_threshold: 99\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        monkeypatch.setenv("NST_CONFIG", str(env_file))
        assert AppConfig.load().mac_detector.flood_threshold == 99

    def test_nst_config_pointing_nowhere_raises(self, monkeypatch: pytest.MonkeyPatch,
                                                tmp_path: Path) -> None:
        monkeypatch.setenv("NST_CONFIG", str(tmp_path / "missing.yaml"))
        with pytest.raises(ConfigurationError, match="not found"):
            AppConfig.load()

    def test_explicit_path_beats_env_var(self, monkeypatch: pytest.MonkeyPatch,
                                         tmp_path: Path) -> None:
        env_file = tmp_path / "env.yaml"
        env_file.write_text("logging:\n  level: ERROR\n")
        explicit = tmp_path / "explicit.yaml"
        explicit.write_text("logging:\n  level: WARNING\n")
        monkeypatch.setenv("NST_CONFIG", str(env_file))
        assert AppConfig.load(config_path=explicit).logging.level == "WARNING"
