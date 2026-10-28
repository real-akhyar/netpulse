"""Per-app aggregation -> nosiness score + plain-English verdict (SPEC §2.3).

Aggregates by app (exe, fallback name), never pid, and keeps session history: a culprit stays
caught after its sockets close. Tracker/suspicious counts are distinct domains/IPs, not sockets.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from netpulse.detect.heuristics import process_flags
from netpulse.models import SEVERITY_RANK, Connection, ProcessAgg


@dataclass
class _App:
    name: str
    exe: Optional[str]
    pid: Optional[int] = None
    connection_ids: set[str] = field(default_factory=set)
    remotes: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    trackers: Counter = field(default_factory=Counter)  # tracker rule -> connections
    tracked_ids: set[str] = field(default_factory=set)  # connections already counted in `trackers`
    suspicious: dict[str, str] = field(default_factory=dict)  # ip -> strongest flag id
    # What a block needs: hosts files match exact names, so keep every tracker hostname seen
    # (not just the blocklist rule), and each suspicious IP's hostname when it has one.
    tracker_hosts: set[str] = field(default_factory=set)
    suspicious_hosts: dict[str, Optional[str]] = field(default_factory=dict)  # ip -> hostname
    beacon: Optional[tuple[str, float]] = None  # (host, period)
    severity: Optional[str] = None  # worst non-info connection flag
    last_seen: float = 0.0


def _worse(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


@dataclass
class BlockTarget:
    """Everything worth blocking for one culprit app."""

    name: str
    exe: Optional[str]
    tracker_domains: set[str]  # exact hostnames contacted + their blocklist rules
    suspicious: dict[str, Optional[str]]  # beaconing / bare IP -> its hostname, if any


class Ranker:
    def __init__(self) -> None:
        self.apps: dict[str, _App] = {}

    def observe(self, conn: Connection, beacon_period: Optional[float] = None) -> None:
        """Fold a (re-)enriched connection into its app's history. Idempotent per connection."""
        app = self.apps.get(conn.app)
        if app is None:
            app = self.apps[conn.app] = _App(name=conn.process_name, exe=conn.process_exe)
        app.pid = conn.pid or app.pid
        app.last_seen = max(app.last_seen, conn.last_seen)
        app.connection_ids.add(conn.id)
        if conn.scope != "public":
            return
        app.remotes.add(conn.raddr)
        if conn.country:
            app.countries.add(conn.country)
        if conn.tracker_rule and conn.id not in app.tracked_ids:
            app.trackers[conn.tracker_rule] += 1
            app.tracked_ids.add(conn.id)
        if conn.tracker_rule:
            app.tracker_hosts.update(h for h in (conn.remote_host, conn.tracker_rule) if h)
        for flag in conn.flags:
            if flag.severity != "info":
                app.severity = _worse(app.severity, flag.severity)
            if flag.id == "beaconing":
                app.suspicious[conn.raddr] = "beaconing"
                app.suspicious_hosts[conn.raddr] = conn.remote_host
                if beacon_period:
                    app.beacon = (conn.remote_host or conn.raddr, beacon_period)
            elif flag.id == "raw_ip":
                app.suspicious.setdefault(conn.raddr, "raw_ip")
                app.suspicious_hosts.setdefault(conn.raddr, conn.remote_host)

    def _aggregate(self, key: str, app: _App) -> ProcessAgg:
        tracker_count = len(app.trackers)
        suspicious_count = len(app.suspicious)
        flags = process_flags(app.name, set(app.trackers))
        severity = app.severity
        for flag in flags:
            severity = _worse(severity, flag.severity)
        nosiness = min(
            100.0,
            tracker_count * 10 + suspicious_count * 8 + len(app.countries) * 2 + len(app.remotes) * 0.5,
        )
        return ProcessAgg(
            app=key,
            pid=app.pid,
            name=app.name,
            exe=app.exe,
            connection_count=len(app.connection_ids),
            distinct_remotes=len(app.remotes),
            distinct_countries=len(app.countries),
            tracker_count=tracker_count,
            suspicious_count=suspicious_count,
            nosiness=round(nosiness, 1),
            verdict_text=self._verdict(app),
            top_trackers=[d for d, _ in app.trackers.most_common(5)],
            flags=flags,
            severity=severity,
        )

    @staticmethod
    def _verdict(app: _App) -> str:
        parts = []
        if app.trackers:
            n, c = len(app.trackers), len(app.countries)
            parts.append(
                f"{app.name} is contacting {n} ad/tracking server{'s' if n != 1 else ''}"
                f" across {c} countr{'ies' if c != 1 else 'y'}"
            )
        if app.beacon:
            host, period = app.beacon
            parts.append(f"{'and ' if parts else app.name + ' '}is quietly beaconing to {host} every ~{period:.0f}s")
        elif app.suspicious:
            n = len(app.suspicious)
            parts.append(f"{'and ' if parts else app.name + ' '}keeps reconnecting to {n} bare IP{'s' if n != 1 else ''} with no hostname")
        if not parts:
            return f"{app.name} — nothing suspicious."
        return " ".join(parts) + "."

    def processes(self) -> list[ProcessAgg]:
        """All apps, noisiest first."""
        return sorted((self._aggregate(k, a) for k, a in self.apps.items()), key=lambda p: (-p.nosiness, p.name.lower()))

    def culprits(self, min_severity: str = "low") -> list[ProcessAgg]:
        """The "Caught" list: apps with a tracker/suspicious finding at or above min_severity."""
        floor = SEVERITY_RANK[min_severity]
        return [
            p for p in self.processes()
            if (p.tracker_count or p.suspicious_count) and SEVERITY_RANK[p.severity or "info"] >= floor
        ]

    def block_targets(self, keys: Optional[list[str]] = None, min_severity: str = "low") -> list[BlockTarget]:
        """Blockable endpoints for the given apps (default: every culprit), noisiest first."""
        wanted = set(keys) if keys is not None else {p.app for p in self.culprits(min_severity)}
        targets = []
        for proc in self.processes():
            app = self.apps.get(proc.app)
            if proc.app not in wanted or app is None:
                continue
            targets.append(BlockTarget(
                name=app.name,
                exe=app.exe,
                tracker_domains=set(app.tracker_hosts),
                suspicious={ip: app.suspicious_hosts.get(ip) for ip in app.suspicious},
            ))
        return targets

    def app_for_pid(self, pid: int) -> Optional[str]:
        return next((key for key, app in self.apps.items() if app.pid == pid), None)
