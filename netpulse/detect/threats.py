"""Known-malware matching against bundled, offline threat-intel snapshots.

Built by scripts/update_threat_lists.py from HaGeZi Threat Intelligence Feeds, the URLhaus mirror
and Feodo Tracker. A hit means the endpoint is listed as malware / phishing / botnet
infrastructure — far stronger than a tracker hit, so it's flagged critical.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DOMAINS_FILE = DATA_DIR / "threat_domains.txt"
IPS_FILE = DATA_DIR / "threat_ips.txt"
# Networks whose IPs are shared by countless sites (CDNs, front doors) and recycled between cloud
# customers. An IP from these says little about one site — never match or block by IP alone.
SHARED_NETWORKS = (
    "google", "amazon", "microsoft", "cloudflare", "akamai", "fastly", "apple", "facebook", "meta platforms",
    "edgecast", "edgio", "limelight", "stackpath", "cdn77", "bunny", "incapsula", "imperva", "sucuri",
)


def is_shared_network(org: Optional[str]) -> bool:
    return bool(org) and any(net in org.lower() for net in SHARED_NETWORKS)


SOURCE_NAMES = {
    "hagezi": "HaGeZi Threat Intelligence",
    "urlhaus": "URLhaus (abuse.ch)",
    "feodo": "Feodo Tracker (abuse.ch)",
}


@dataclass(frozen=True)
class ThreatHit:
    indicator: str  # the listed domain or IP
    kind: str  # "domain" | "ip"
    source: str  # human-readable list name
    family: str = ""  # malware family, when the list says

    def describe(self) -> str:
        what = f"{self.family} botnet server" if self.family else "malware infrastructure"
        return f"listed as {what} by {self.source}"


def _rows(path: Path) -> Iterable[list[str]]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    yield line.rstrip("\n").split("\t")
    except OSError:
        log.warning("threat list not found: %s (known-malware matching disabled)", path)


class ThreatIntel:
    def __init__(self, domains_file: Path = DOMAINS_FILE, ips_file: Path = IPS_FILE):
        self.domains: dict[str, str] = {row[0]: row[1] if len(row) > 1 else "" for row in _rows(domains_file)}
        self.ips: dict[str, tuple[str, str]] = {
            row[0]: (row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else "") for row in _rows(ips_file)
        }
        log.info("loaded %d malware domains, %d malware IPs", len(self.domains), len(self.ips))

    def match_host(self, host: Optional[str]) -> Optional[ThreatHit]:
        """The host itself or any parent domain on the list."""
        if not host:
            return None
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                source = self.domains[candidate]
                return ThreatHit(candidate, "domain", SOURCE_NAMES.get(source, source))
        return None

    def match_ip(self, ip: str) -> Optional[ThreatHit]:
        hit = self.ips.get(ip)
        if hit is None:
            return None
        source, family = hit
        return ThreatHit(ip, "ip", SOURCE_NAMES.get(source, source), family)

    def match(self, ip: str, names: Iterable[Optional[str]] = ()) -> Optional[ThreatHit]:
        """IP first (labelled botnet lists are the most specific), then every name in the CNAME chain."""
        hit = self.match_ip(ip)
        if hit:
            return hit
        for name in names:
            hit = self.match_host(name)
            if hit:
                return hit
        return None
