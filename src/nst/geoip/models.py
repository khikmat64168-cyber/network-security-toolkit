"""GeoResult — geolocation data for one IP address or hostname."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GeoResult:
    """
    Geolocation record returned by GeoIPClient.lookup().

    Attributes
    ──────────
    ip          — The address or hostname that was queried.
    success     — False when the API call failed or the IP is unroutable.
    is_private  — True for RFC-1918 / loopback / link-local addresses.
    error       — Human-readable failure reason (empty on success).
    """

    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    is_private: bool = False
    success: bool = True
    error: str = ""

    @property
    def flag(self) -> str:
        """Unicode regional-indicator flag emoji for *country_code* (e.g. 🇺🇸)."""
        if not self.country_code or len(self.country_code) != 2:
            return "🌐"
        offset = 0x1F1E6 - ord("A")
        return "".join(chr(offset + ord(c)) for c in self.country_code.upper())

    @property
    def location(self) -> str:
        """'City, Country' string, gracefully degrading when fields are empty."""
        if self.is_private:
            return "Private Range"
        parts = [p for p in (self.city, self.country) if p]
        return ", ".join(parts) if parts else "Unknown"
