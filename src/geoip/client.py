"""
GeoIPClient — cached HTTP geolocation via ip-api.com.

Design decisions
────────────────
* Uses only stdlib (urllib, json, ipaddress) — no extra dependency.
* Private / loopback / link-local IPs are detected locally and never
  sent to the API; they return a GeoResult with is_private=True.
* All results are cached in memory; a second lookup for the same
  address is free.
* Errors (network timeout, bad JSON, API failure) are captured in
  GeoResult.success/error so callers never need to catch exceptions.
* Timeout is deliberately short (3 s) to avoid stalling packet capture
  or CLI output.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.request
from typing import Dict, List

from src.geoip.models import GeoResult

_API_URL = (
    "http://ip-api.com/json/{target}"
    "?fields=status,message,country,countryCode,region,city,isp,lat,lon"
)
_TIMEOUT = 3  # seconds


def _is_private(target: str) -> bool:
    """Return True when *target* is a private / loopback / link-local IP."""
    try:
        return ipaddress.ip_address(target).is_private
    except ValueError:
        return False  # not a bare IP (hostname) — let the API handle it


class GeoIPClient:
    """
    Resolves IP addresses (and hostnames) to geolocation data.

    Usage
    ─────
        client = GeoIPClient()
        result = client.lookup("8.8.8.8")
        print(result.flag, result.country)   # 🇺🇸 United States
    """

    def __init__(self) -> None:
        self._cache: Dict[str, GeoResult] = {}

    def lookup(self, target: str) -> GeoResult:
        """
        Return geolocation for *target* (IP address or hostname).

        Results are cached — repeated calls for the same target are free.
        Never raises; errors appear in GeoResult.success / GeoResult.error.
        """
        if target in self._cache:
            return self._cache[target]

        if _is_private(target):
            result = GeoResult(ip=target, is_private=True, country="Private Range")
        else:
            try:
                result = self._fetch(target)
            except Exception as exc:
                result = GeoResult(ip=target, success=False, error=str(exc))

        self._cache[target] = result
        return result

    def lookup_batch(self, targets: List[str]) -> Dict[str, GeoResult]:
        """Look up multiple targets and return {target: GeoResult}."""
        return {t: self.lookup(t) for t in targets}

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    # ── Private ────────────────────────────────────────────────────────────────

    def _fetch(self, target: str) -> GeoResult:
        url = _API_URL.format(target=target)
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:  # noqa: S310
            data: dict = json.loads(resp.read().decode())

        if data.get("status") != "success":
            return GeoResult(
                ip=target,
                success=False,
                error=data.get("message", "API returned failure status"),
            )

        return GeoResult(
            ip=target,
            country=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("region", ""),
            city=data.get("city", ""),
            isp=data.get("isp", ""),
            latitude=float(data.get("lat", 0.0)),
            longitude=float(data.get("lon", 0.0)),
        )
