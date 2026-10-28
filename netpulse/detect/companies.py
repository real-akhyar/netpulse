"""Who's behind a tracker domain — for the privacy report's "trackers by company"."""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

COMPANIES_FILE = Path(__file__).resolve().parent.parent / "data" / "tracker_companies.txt"


@functools.lru_cache(maxsize=1)
def _companies() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for line in COMPANIES_FILE.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#") and "\t" in line:
                domain, company = line.split("\t", 1)
                out[domain.strip().lower()] = company.strip()
    except OSError:
        log.warning("tracker company map not found: %s", COMPANIES_FILE)
    return out


def company_for(domain: Optional[str]) -> Optional[str]:
    """Company for a domain or any parent domain — the most specific entry wins."""
    if not domain:
        return None
    companies = _companies()
    labels = domain.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        hit = companies.get(".".join(labels[i:]))
        if hit:
            return hit
    return None
