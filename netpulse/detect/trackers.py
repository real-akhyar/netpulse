"""Bundled offline tracker/ad blocklist with suffix matching (SPEC §2.1).

Accepts plain-domain lists (OISD `domainswild2`), wildcard (`*.x`), adblock (`||x^`) and hosts-file
(`0.0.0.0 x`, e.g. StevenBlack) lines, so the bundled snapshot can be swapped without code changes.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
# OISD small snapshot + netpulse's curated supplement (big analytics/ad/telemetry domains OISD omits).
TRACKER_FILES = (DATA_DIR / "trackers.txt", DATA_DIR / "trackers_extra.txt")
_HOSTS_SINKS = {"0.0.0.0", "127.0.0.1", "::", "::1"}


def _parse_line(line: str) -> Optional[str]:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("!"):
        return None
    parts = line.split()
    if len(parts) >= 2 and parts[0] in _HOSTS_SINKS:
        line = parts[1]
    elif len(parts) != 1:
        return None
    line = line.removeprefix("||").removesuffix("^").removeprefix("*.").lower().rstrip(".")
    if "." not in line or line in ("localhost", "localhost.localdomain"):
        return None
    return line


class TrackerList:
    def __init__(self, paths: Iterable[Path] = TRACKER_FILES):
        self.domains: set[str] = set()
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    for raw in f:
                        domain = _parse_line(raw)
                        if domain:
                            self.domains.add(domain)
            except OSError:
                log.warning("tracker list not found: %s", path)
        log.info("loaded %d tracker domains", len(self.domains))

    def match(self, host: Optional[str]) -> Optional[str]:
        """Return the blocklist rule `host` falls under (itself or a parent domain), else None."""
        if not host:
            return None
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):  # never match a bare TLD
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return candidate
        return None

    def match_any(self, hosts: Iterable[Optional[str]]) -> Optional[str]:
        for host in hosts:
            rule = self.match(host)
            if rule:
                return rule
        return None
