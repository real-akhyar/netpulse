"""Flags that bite even fully offline / on raw IPs (SPEC §2.2, as amended by DECISIONS:
beaconing is keyed on repeated NEW connections per (app, remote_ip, rport); unusual_port is
info-only and never makes a connection suspicious)."""

from __future__ import annotations

import statistics
from typing import Optional

from netpulse.models import Connection, Flag

BEACON_MIN_ARRIVALS = 4
# Regularity = median absolute deviation / median of inter-arrival gaps. Median-based so one
# outlier gap (a missed poll, or deliberate beacon jitter) doesn't hide a beacon.
BEACON_MAX_SPREAD = 0.25
BEACON_MIN_PERIOD = 3.0  # seconds; faster than this is a connection pool, not a beacon
RAW_IP_MIN_ARRIVALS = 3
MANY_TRACKERS_K = 3

# Ports normal apps use to public hosts. Anything else gets an info-only `unusual_port`.
COMMON_PORTS = {
    80, 443, 53, 853, 123,  # web, DNS, DoT, NTP
    25, 465, 587, 110, 995, 143, 993,  # mail
    22, 5222, 5223, 5228, 5229, 5230,  # ssh, XMPP / Apple push / Google FCM
    3478, 3479, 3480, 3481, 19302,  # STUN/TURN (Teams, Meet, WebRTC)
    8801, 8802, 8803, 8804, 8805, 8806, 8807, 8808, 8809, 8810,  # Zoom
    4070,  # Spotify
    1935, 8080, 8443,
}


def beacon_period(arrivals: list[float]) -> Optional[float]:
    """Median period if arrivals are regular enough to be a beacon, else None."""
    if len(arrivals) < BEACON_MIN_ARRIVALS:
        return None
    gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
    period = statistics.median(gaps)
    if period < BEACON_MIN_PERIOD:
        return None
    spread = statistics.median(abs(g - period) for g in gaps) / period
    if spread > BEACON_MAX_SPREAD:
        return None
    return period


def _where(conn: Connection) -> str:
    return conn.country or "unknown country"


def connection_flags(conn: Connection, arrivals: list[float], resolved: bool) -> list[Flag]:
    """Per-connection flags. `resolved` = hostname lookup has finished (so a missing host is real)."""
    if conn.scope != "public":
        return []
    flags: list[Flag] = []
    host = conn.remote_host or conn.raddr
    if conn.tracker_rule:
        flags.append(Flag(
            id="tracker_contact", severity="medium",
            title=f"Contacted ad/tracker domain {conn.tracker_rule}",
            detail=f"{conn.process_name} connected to {host}, which is on the bundled tracker blocklist.",
        ))
    period = beacon_period(arrivals)
    if period is not None:
        flags.append(Flag(
            id="beaconing", severity="medium",
            title=f"Regular beaconing to {conn.raddr} ({_where(conn)})",
            detail=f"{conn.process_name} opened {len(arrivals)} new connections to {host}:{conn.rport} about every {period:.0f}s.",
        ))
    if resolved and not conn.remote_host and len(arrivals) >= RAW_IP_MIN_ARRIVALS:
        org = f", owned by {conn.org}" if conn.org else ""
        flags.append(Flag(
            id="raw_ip", severity="low",
            title=f"Talks to a bare IP with no hostname ({conn.raddr})",
            detail=f"{conn.process_name} keeps reconnecting to {conn.raddr} ({_where(conn)}{org}) with no DNS name behind it.",
        ))
    if conn.rport not in COMMON_PORTS:
        flags.append(Flag(
            id="unusual_port", severity="info",
            title=f"Non-standard port {conn.rport} to {host}",
            detail="Informational only — many apps legitimately use their own ports.",
        ))
    return flags


def categorize(conn: Connection) -> str:
    if conn.scope != "public":
        return "local"
    ids = {f.id for f in conn.flags}
    if "tracker_contact" in ids:
        return "tracker"
    if ids & {"beaconing", "raw_ip"}:
        return "suspicious"
    return "normal"


def process_flags(name: str, tracker_domains: set[str]) -> list[Flag]:
    if len(tracker_domains) >= MANY_TRACKERS_K:
        return [Flag(
            id="many_trackers", severity="high",
            title=f"{name} contacted {len(tracker_domains)} trackers",
            detail=", ".join(sorted(tracker_domains)[:8]),
        )]
    return []
