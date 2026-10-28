"""Offline IP -> country/lat/lon/org (SPEC §1.3, per DECISIONS: DB-IP Country Lite + country
centroids instead of City Lite). Bundled data only; a missing DB degrades to None, never raises."""

from __future__ import annotations

import csv
import functools
import logging
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import maxminddb

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
COUNTRY_DB = DATA_DIR / "dbip-country-lite.mmdb"
ASN_DB = DATA_DIR / "dbip-asn-lite.mmdb"
CENTROIDS = DATA_DIR / "country_centroids.csv"
OWN_IP_URL = "https://api.ipify.org"


@dataclass(frozen=True)
class GeoInfo:
    country: Optional[str] = None  # ISO-2
    country_name: Optional[str] = None
    city: Optional[str] = None  # Country Lite has no city; kept for the model's shape
    lat: Optional[float] = None
    lon: Optional[float] = None
    org: Optional[str] = None


def _open(path: Path):
    try:
        return maxminddb.open_database(str(path))
    except Exception:
        log.warning("GeoIP database not found or unreadable: %s (locations will show as IP only)", path)
        return None


class GeoIP:
    def __init__(self) -> None:
        self._country = _open(COUNTRY_DB)
        self._asn = _open(ASN_DB)
        self.centroids: dict[str, tuple[float, float, str]] = {}
        try:
            with open(CENTROIDS, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    self.centroids[row["code"]] = (float(row["lat"]), float(row["lon"]), row["name"])
        except Exception:
            log.warning("country centroid table missing: %s", CENTROIDS)

    @functools.lru_cache(maxsize=8192)
    def lookup(self, ip: str) -> GeoInfo:
        code = name = org = None
        try:
            rec = self._country.get(ip) if self._country else None
            if rec and rec.get("country"):
                code = rec["country"].get("iso_code")
                name = rec["country"].get("names", {}).get("en")
        except Exception:
            log.debug("country lookup failed for %s", ip, exc_info=True)
        try:
            rec = self._asn.get(ip) if self._asn else None
            if rec:
                org = rec.get("autonomous_system_organization")
        except Exception:
            log.debug("ASN lookup failed for %s", ip, exc_info=True)
        lat = lon = None
        if code in self.centroids:
            lat, lon, centroid_name = self.centroids[code]
            name = name or centroid_name
        return GeoInfo(country=code, country_name=name, lat=lat, lon=lon, org=org)

    def own_origin(self, timeout: float = 1.5) -> Optional[dict]:
        """Best-effort {lat, lon, label} for the globe origin from our public IP. Blocking (call
        via a thread); returns None when offline/blocked. netpulse's own traffic is filtered out."""
        try:
            with urllib.request.urlopen(OWN_IP_URL, timeout=timeout) as resp:
                ip = resp.read(64).decode("ascii", errors="ignore").strip()
        except Exception:
            return None
        geo = self.lookup(ip)
        if geo.lat is None:
            return None
        return {"lat": geo.lat, "lon": geo.lon, "label": f"You ({geo.country_name or geo.country})"}

    def fallback_origin(self, countries: Iterable[Optional[str]]) -> dict:
        """Centroid of the most common remote country, else (0, 0)."""
        common = Counter(c for c in countries if c in self.centroids).most_common(1)
        if common:
            lat, lon, name = self.centroids[common[0][0]]
            return {"lat": lat, "lon": lon, "label": f"You (near {name})"}
        return {"lat": 0.0, "lon": 0.0, "label": "You"}
