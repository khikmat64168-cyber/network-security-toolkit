"""
Tests for Phase 12 — IP Geolocation.

Coverage
────────
* GeoResult properties           (models.py)
* _is_private                    (client.py)
* GeoIPClient — caching, private, error, success (client.py)
* display helpers                (display.py)
* report integration             (builder.add_geo, renderer geo column)
* geoip CLI smoke                (cli/main.py)
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nst.geoip.client import GeoIPClient, _is_private
from nst.geoip.display import format_city, format_location
from nst.geoip.models import GeoResult
from nst.reporter.builder import ReportBuilder, _resolve_host
from nst.reporter.models import InterfaceInfo, ReportData, TLSFinding
from nst.reporter.renderer import render


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ok_geo(ip: str = "8.8.8.8") -> GeoResult:
    return GeoResult(
        ip=ip,
        country="United States",
        country_code="US",
        region="Virginia",
        city="Ashburn",
        isp="AS15169 Google LLC",
        latitude=39.03,
        longitude=-77.5,
    )


def _mock_urlopen(data: dict):
    """Context-manager mock for urllib.request.urlopen."""
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(data).encode()
    return mock


def _finding(
    host: str = "example.com",
    severity: str = "ok",
    geo: GeoResult | None = None,
) -> TLSFinding:
    return TLSFinding(
        host=host,
        port=443,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        subject="CN=example.com",
        issuer="CN=Let's Encrypt",
        days_until_expiry=90,
        issues=[],
        severity=severity,
        geo=geo,
    )


# ──────────────────────────────────────────────────────────────────────────────
# GeoResult — model
# ──────────────────────────────────────────────────────────────────────────────

class TestGeoResult:
    def test_flag_us(self):
        r = GeoResult(ip="8.8.8.8", country_code="US")
        assert r.flag == "🇺🇸"

    def test_flag_gb(self):
        r = GeoResult(ip="1.2.3.4", country_code="GB")
        assert r.flag == "🇬🇧"

    def test_flag_empty_code_returns_globe(self):
        r = GeoResult(ip="1.2.3.4", country_code="")
        assert r.flag == "🌐"

    def test_flag_single_char_returns_globe(self):
        r = GeoResult(ip="1.2.3.4", country_code="U")
        assert r.flag == "🌐"

    def test_location_city_and_country(self):
        r = _ok_geo()
        assert r.location == "Ashburn, United States"

    def test_location_country_only(self):
        r = GeoResult(ip="1.2.3.4", country="Germany", city="")
        assert r.location == "Germany"

    def test_location_private(self):
        r = GeoResult(ip="192.168.1.1", is_private=True)
        assert r.location == "Private Range"

    def test_location_empty_fields_returns_unknown(self):
        r = GeoResult(ip="1.2.3.4")
        assert r.location == "Unknown"


# ──────────────────────────────────────────────────────────────────────────────
# _is_private
# ──────────────────────────────────────────────────────────────────────────────

class TestIsPrivate:
    def test_loopback(self):
        assert _is_private("127.0.0.1") is True

    def test_rfc1918_10(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert _is_private("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private("192.168.1.100") is True

    def test_public_ip_false(self):
        assert _is_private("8.8.8.8") is False

    def test_hostname_returns_false(self):
        assert _is_private("github.com") is False

    def test_invalid_string_returns_false(self):
        assert _is_private("not-an-ip") is False


# ──────────────────────────────────────────────────────────────────────────────
# GeoIPClient
# ──────────────────────────────────────────────────────────────────────────────

class TestGeoIPClient:
    def test_private_ip_skips_api(self):
        client = GeoIPClient()
        with patch("urllib.request.urlopen") as mock_open:
            result = client.lookup("192.168.1.1")
        mock_open.assert_not_called()
        assert result.is_private is True

    def test_private_ip_location(self):
        client = GeoIPClient()
        result = client.lookup("127.0.0.1")
        assert result.is_private is True

    def test_successful_lookup(self):
        client = GeoIPClient()
        api_data = {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "region": "VA",
            "city": "Ashburn",
            "isp": "AS15169 Google LLC",
            "lat": 39.03,
            "lon": -77.5,
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_data)):
            result = client.lookup("8.8.8.8")
        assert result.success is True
        assert result.country == "United States"
        assert result.country_code == "US"
        assert result.city == "Ashburn"
        assert result.isp == "AS15169 Google LLC"
        assert result.latitude == 39.03

    def test_api_failure_status(self):
        client = GeoIPClient()
        api_data = {"status": "fail", "message": "private range"}
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_data)):
            result = client.lookup("8.8.8.8")
        assert result.success is False
        assert "private range" in result.error

    def test_network_error_captured(self):
        client = GeoIPClient()
        with patch("urllib.request.urlopen", side_effect=OSError("timeout")):
            result = client.lookup("8.8.8.8")
        assert result.success is False
        assert result.error != ""

    def test_result_is_cached(self):
        client = GeoIPClient()
        api_data = {
            "status": "success", "country": "US", "countryCode": "US",
            "region": "", "city": "", "isp": "", "lat": 0, "lon": 0,
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_data)) as m:
            client.lookup("8.8.8.8")
            client.lookup("8.8.8.8")
        assert m.call_count == 1

    def test_failures_are_not_cached(self):
        client = GeoIPClient()
        with patch.object(client, "_fetch", side_effect=OSError("offline")) as fetch:
            first = client.lookup("8.8.8.8")
            second = client.lookup("8.8.8.8")
        assert not first.success and not second.success
        assert fetch.call_count == 2
        assert client.cache_size == 0

    def test_cache_size_increments(self):
        client = GeoIPClient()
        client.lookup("192.168.1.1")
        client.lookup("10.0.0.1")
        assert client.cache_size == 2

    def test_lookup_batch(self):
        client = GeoIPClient()
        results = client.lookup_batch(["192.168.0.1", "10.0.0.1"])
        assert len(results) == 2
        assert all(r.is_private for r in results.values())


# ──────────────────────────────────────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────────────────────────────────────

class TestDisplayHelpers:
    def test_format_location_ok(self):
        result = format_location(_ok_geo())
        assert "United States" in result

    def test_format_location_private(self):
        r = GeoResult(ip="192.168.1.1", is_private=True)
        assert "Private" in format_location(r)

    def test_format_location_failure(self):
        r = GeoResult(ip="1.2.3.4", success=False)
        assert "Unknown" in format_location(r)

    def test_format_city_ok(self):
        result = format_city(_ok_geo())
        assert "Ashburn" in result

    def test_format_city_private(self):
        r = GeoResult(ip="10.0.0.1", is_private=True)
        assert "—" in format_city(r)


# ──────────────────────────────────────────────────────────────────────────────
# Report builder — add_geo
# ──────────────────────────────────────────────────────────────────────────────

class TestReportBuilderGeo:
    def _make_tls_result(self, host: str = "github.com") -> MagicMock:
        r = MagicMock()
        r.host = host
        r.port = 443
        r.tls_version = "TLSv1.3"
        r.cipher_suite = "TLS_AES_256_GCM_SHA384"
        r.subject = f"CN={host}"
        r.issuer = "CN=Let's Encrypt"
        r.error = None
        r.critical_count = 0
        r.high_count = 0
        r.days_until_expiry = 90
        r.issues = []
        return r

    def test_add_geo_populates_finding(self):
        mock_client = MagicMock()
        mock_client.lookup.return_value = _ok_geo()

        with patch("nst.reporter.builder._resolve_host", return_value="140.82.114.3"):
            data = (
                ReportBuilder()
                .add_tls_results([self._make_tls_result("github.com")])
                .add_geo(mock_client)
                .build()
            )

        assert data.tls_findings[0].geo is not None
        assert data.tls_findings[0].geo.country == "United States"

    def test_add_geo_failure_leaves_none(self):
        mock_client = MagicMock()
        mock_client.lookup.side_effect = Exception("network error")

        with patch("nst.reporter.builder._resolve_host", return_value="1.2.3.4"):
            data = (
                ReportBuilder()
                .add_tls_results([self._make_tls_result()])
                .add_geo(mock_client)
                .build()
            )

        assert data.tls_findings[0].geo is None

    def test_resolve_host_returns_none_on_failure(self):
        with patch("socket.gethostbyname", side_effect=OSError):
            assert _resolve_host("nonexistent.invalid") is None


# ──────────────────────────────────────────────────────────────────────────────
# Renderer — geo column
# ──────────────────────────────────────────────────────────────────────────────

class TestRendererGeo:
    def _report_with_geo(self) -> ReportData:
        f = _finding(host="github.com", geo=_ok_geo("140.82.114.3"))
        return ReportData(
            generated_at=datetime(2026, 7, 17, 12, 0, 0),
            tls_findings=[f],
        )

    def test_render_shows_location_column_when_geo_present(self):
        html = render(self._report_with_geo())
        assert "Location" in html

    def test_render_shows_country_name(self):
        html = render(self._report_with_geo())
        assert "United States" in html

    def test_render_no_geo_column_when_no_geo(self):
        data = ReportData(
            generated_at=datetime(2026, 7, 17, 12, 0, 0),
            tls_findings=[_finding()],
        )
        html = render(data)
        assert "Location" not in html

    def test_render_private_ip_shows_private(self):
        geo = GeoResult(ip="192.168.1.1", is_private=True)
        f = _finding(geo=geo)
        data = ReportData(generated_at=datetime.now(), tls_findings=[f])
        html = render(data)
        assert "Private" in html


# ──────────────────────────────────────────────────────────────────────────────
# CLI smoke tests
# ──────────────────────────────────────────────────────────────────────────────

class TestGeoIPCLI:
    def test_geoip_no_args_exits_1(self):
        from nst.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["geoip"])
        assert result.exit_code == 1

    def test_geoip_private_ip_succeeds(self):
        from nst.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["geoip", "192.168.1.1"])
        assert result.exit_code == 0

    def test_geoip_mocked_public_ip(self):
        from nst.cli.main import cli

        api_data = {
            "status": "success", "country": "Germany", "countryCode": "DE",
            "region": "BE", "city": "Berlin", "isp": "Hetzner",
            "lat": 52.52, "lon": 13.40,
        }
        runner = CliRunner()
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(api_data)):
            result = runner.invoke(cli, ["geoip", "5.9.0.1"])
        assert result.exit_code == 0
        assert "Germany" in result.output
