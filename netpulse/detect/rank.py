"""Per-app aggregation -> nosiness score + plain-English verdict (SPEC §2.3).

Aggregates by app (exe, fallback name), never pid, and keeps session history: a culprit stays
caught after its sockets close. Tracker/suspicious counts are distinct domains/IPs, not sockets.

Each app keeps one record per endpoint (remote IP + port) with its raw findings; the culprit view
is folded from those records on demand. That keeps trust exact: trusting a domain or an app hides
its findings everywhere at once, and untrusting brings them straight back.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from netpulse.detect.heuristics import process_flags
from netpulse.models import SEVERITY_RANK, Connection, Flag, ProcessAgg, ProcessInfo
from netpulse.trust import Trust

# App-level flags about *who the app is* (heuristics.process_flags), as opposed to many_trackers.
PROCESS_ALERTS = {"masquerading", "silent_tool_online", "dual_use_tool_online", "risky_location", "bad_signature", "unsigned"}
ALERT_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 3, "info": 0}
MAX_ENDPOINTS_PER_APP = 3000


@dataclass
class _Endpoint:
    ip: str
    port: int
    host: Optional[str]
    country: Optional[str]
    org: Optional[str]
    tracker_rule: Optional[str]
    threat_indicator: Optional[str]
    threat: Optional[str]
    flags: list[Flag]
    beacon_period: Optional[float]
    last_seen: float
    hits: int = 1

    @property
    def notable(self) -> bool:
        return bool(self.tracker_rule or self.threat_indicator or any(f.severity != "info" for f in self.flags))


@dataclass
class _App:
    name: str
    exe: Optional[str]
    pid: Optional[int] = None
    info: Optional[ProcessInfo] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    connection_ids: set[str] = field(default_factory=set)
    endpoints: dict[tuple[str, int], _Endpoint] = field(default_factory=dict)


@dataclass
class Facts:
    """What an app did, after trust is applied — everything verdicts, counts and exports need."""

    remotes: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    trackers: Counter = field(default_factory=Counter)  # tracker rule -> hits
    # Hosts files match exact names, so keep every tracker hostname seen (not just the rule).
    tracker_hosts: set[str] = field(default_factory=set)
    malware: dict[str, str] = field(default_factory=dict)  # listed indicator -> description
    suspicious: dict[str, str] = field(default_factory=dict)  # ip -> strongest flag id
    suspicious_hosts: dict[str, Optional[str]] = field(default_factory=dict)  # ip -> hostname
    suspicious_orgs: dict[str, Optional[str]] = field(default_factory=dict)  # ip -> network owner
    beacon: Optional[tuple[str, float]] = None  # (host, period)
    severity: Optional[str] = None  # worst non-info connection flag
    last_remote: Optional[str] = None  # "host, country" of the latest public endpoint, for verdicts


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
    orgs: dict[str, Optional[str]] = field(default_factory=dict)  # suspicious IP -> network owner


class Ranker:
    def __init__(self, trust: Optional[Trust] = None) -> None:
        self.apps: dict[str, _App] = {}
        self.trust = trust or Trust()

    # ---- recording -------------------------------------------------------

    def observe(self, conn: Connection, beacon_period: Optional[float] = None) -> None:
        """Record a (re-)enriched connection under its app. Idempotent per connection; the
        latest classification of an endpoint wins. Pass the *untrusted* findings — trust is
        applied when folding, so it can be undone."""
        app = self.apps.get(conn.app)
        if app is None:
            app = self.apps[conn.app] = _App(name=conn.process_name, exe=conn.process_exe)
        app.pid = conn.pid or app.pid
        app.first_seen = min(app.first_seen or conn.first_seen, conn.first_seen)
        app.last_seen = max(app.last_seen, conn.last_seen)
        new_connection = conn.id not in app.connection_ids
        app.connection_ids.add(conn.id)
        if conn.scope != "public":
            return
        key = (conn.raddr, conn.rport)
        old = app.endpoints.get(key)
        app.endpoints[key] = _Endpoint(
            ip=conn.raddr, port=conn.rport, host=conn.remote_host or (old.host if old else None),
            country=conn.country, org=conn.org,
            tracker_rule=conn.tracker_rule or (old.tracker_rule if old else None),
            threat_indicator=conn.threat_indicator or (old.threat_indicator if old else None),
            threat=conn.threat or (old.threat if old else None),
            flags=list(conn.flags), beacon_period=beacon_period or (old.beacon_period if old else None),
            last_seen=max(conn.last_seen, old.last_seen if old else 0.0),
            hits=(old.hits + (1 if new_connection else 0)) if old else 1,
        )
        if len(app.endpoints) > MAX_ENDPOINTS_PER_APP:
            quiet = sorted((e for e in app.endpoints.values() if not e.notable), key=lambda e: e.last_seen)
            for e in quiet[: len(app.endpoints) - MAX_ENDPOINTS_PER_APP]:
                del app.endpoints[(e.ip, e.port)]

    def set_info(self, key: str, info: ProcessInfo) -> None:
        app = self.apps.get(key)
        if app is not None:
            app.info = info

    # ---- folding (trust applied here) ------------------------------------

    def facts(self, key: str) -> Facts:
        f = Facts()
        app = self.apps.get(key)
        if app is None:
            return f
        latest: Optional[_Endpoint] = None
        for ep in app.endpoints.values():
            f.remotes.add(ep.ip)
            if ep.country:
                f.countries.add(ep.country)
            if latest is None or ep.last_seen >= latest.last_seen:
                latest = ep
            if self.trust.covers_any(ep.host, ep.tracker_rule, ep.threat_indicator):
                continue
            if ep.tracker_rule:
                f.trackers[ep.tracker_rule] += ep.hits
                f.tracker_hosts.update(h for h in (ep.host, ep.tracker_rule) if h)
            if ep.threat_indicator:
                f.malware[ep.threat_indicator] = ep.threat or "listed as malware infrastructure"
                f.suspicious[ep.ip] = "known_malware"  # its IP and hostname go into block exports
                f.suspicious_hosts[ep.ip] = ep.host
            for flag in ep.flags:
                if flag.severity != "info":
                    f.severity = _worse(f.severity, flag.severity)
                if flag.id == "beaconing":
                    if f.suspicious.get(ep.ip) != "known_malware":
                        f.suspicious[ep.ip] = "beaconing"
                    f.suspicious_hosts[ep.ip] = ep.host
                    if ep.beacon_period:
                        f.beacon = (ep.host or ep.ip, ep.beacon_period)
                elif flag.id in ("raw_ip", "suspicious_process"):
                    f.suspicious.setdefault(ep.ip, flag.id)
                    f.suspicious_hosts.setdefault(ep.ip, ep.host)
            if ep.ip in f.suspicious:
                f.suspicious_orgs[ep.ip] = ep.org  # block exports skip shared CDN IPs
        if latest is not None:
            f.last_remote = (latest.host or latest.ip) + (f", {latest.country}" if latest.country else "")
        return f

    def _flags(self, app: _App, f: Facts) -> list[Flag]:
        return process_flags(app.name, set(f.trackers), app.info, online=bool(f.remotes), remote=f.last_remote)

    def app_flags(self, key: str) -> list[Flag]:
        app = self.apps.get(key)
        return self._flags(app, self.facts(key)) if app else []

    def is_trusted(self, key: str) -> bool:
        return key in self.trust.apps

    def process_alert(self, key: str) -> Optional[Flag]:
        """The app's worst suspicious-process alert at high/critical, if any — used to mark every
        public connection of that app suspicious, whatever it talks to. None for trusted apps."""
        app = self.apps.get(key)
        if app is None or self.is_trusted(key):
            return None
        last = max(app.endpoints.values(), key=lambda e: e.last_seen, default=None)
        remote = ((last.host or last.ip) + (f", {last.country}" if last.country else "")) if last else None
        # online=True: we're asking on behalf of a public connection, even if it's the app's first.
        flags = process_flags(app.name, set(), app.info, online=True, remote=remote)
        alerts = [f for f in flags if f.id in PROCESS_ALERTS and SEVERITY_RANK[f.severity] >= SEVERITY_RANK["high"]]
        return max(alerts, key=lambda f: SEVERITY_RANK[f.severity], default=None)

    def _aggregate(self, key: str, app: _App) -> ProcessAgg:
        f = self.facts(key)
        trusted = self.is_trusted(key)
        tracker_count = len(f.trackers)
        suspicious_count = len(f.suspicious)
        flags = self._flags(app, f)
        alerts = [x for x in flags if x.id in PROCESS_ALERTS and SEVERITY_RANK[x.severity] >= SEVERITY_RANK["medium"]]
        severity = f.severity
        for flag in flags:
            severity = _worse(severity, flag.severity)
        nosiness = min(
            100.0,
            tracker_count * 10 + suspicious_count * 8 + len(f.countries) * 2 + len(f.remotes) * 0.5
            + sum(ALERT_WEIGHT[x.severity] for x in flags if x.id in PROCESS_ALERTS)
            + len(f.malware) * ALERT_WEIGHT["critical"],
        )
        return ProcessAgg(
            app=key,
            pid=app.pid,
            name=app.name,
            exe=app.exe,
            connection_count=len(app.connection_ids),
            distinct_remotes=len(f.remotes),
            distinct_countries=len(f.countries),
            tracker_count=tracker_count,
            suspicious_count=suspicious_count,
            nosiness=round(nosiness, 1),
            verdict_text=self._verdict(app, f, alerts),
            alert_count=len(alerts),
            malware_count=len(f.malware),
            malware=[f"{i} — {d}" for i, d in list(f.malware.items())[:5]],
            top_trackers=[d for d, _ in f.trackers.most_common(5)],
            flags=flags,
            severity=severity,
            info=app.info,
            first_seen=app.first_seen,
            last_seen=app.last_seen,
            trusted=trusted,
        )

    @staticmethod
    def _verdict(app: _App, f: Facts, alerts: list[Flag]) -> str:
        """Strongest evidence first: a listed malware server, then who the app is (process
        alerts), then what it does (trackers, beacons, bare IPs)."""
        leads = []
        if f.malware:
            indicator, desc = next(iter(f.malware.items()))
            more = len(f.malware) - 1
            leads.append(f"{app.name} connected to {indicator}, which is {desc}" + (
                f" — and {more} more known-malware endpoint{'s' if more != 1 else ''}." if more else "."))
        if alerts:
            leads.append(max(alerts, key=lambda x: SEVERITY_RANK[x.severity]).detail)
        rest = Ranker._behaviour(app, f)
        if not leads:
            return rest or f"{app.name} — nothing suspicious."
        return " ".join(leads) + (f" Also: {rest}" if rest else "")

    @staticmethod
    def _behaviour(app: _App, f: Facts) -> str:
        parts = []
        if f.trackers:
            n, c = len(f.trackers), len(f.countries)
            parts.append(
                f"{app.name} is contacting {n} ad/tracking server{'s' if n != 1 else ''}"
                f" across {c} countr{'ies' if c != 1 else 'y'}"
            )
        if f.beacon:
            host, period = f.beacon
            parts.append(f"{'and ' if parts else app.name + ' '}is quietly beaconing to {host} every ~{period:.0f}s")
        elif bare := [ip for ip, kind in f.suspicious.items() if kind == "raw_ip"]:
            # Only genuine no-hostname IPs: a flagged app's other endpoints are covered by its alert.
            n = len(bare)
            parts.append(f"{'and ' if parts else app.name + ' '}keeps reconnecting to {n} bare IP{'s' if n != 1 else ''} with no hostname")
        return " ".join(parts) + "." if parts else ""

    # ---- views -----------------------------------------------------------

    def processes(self) -> list[ProcessAgg]:
        """All apps, noisiest first."""
        return sorted((self._aggregate(k, a) for k, a in self.apps.items()), key=lambda p: (-p.nosiness, p.name.lower()))

    def culprits(self, min_severity: str = "low") -> list[ProcessAgg]:
        """The "Caught" list: apps with a tracker/suspicious finding at or above min_severity.
        Trusted apps are left out — unless they touched known malware, which trust never hides."""
        floor = SEVERITY_RANK[min_severity]
        return [
            p for p in self.processes()
            if (p.tracker_count or p.suspicious_count or p.alert_count or p.malware_count)
            and SEVERITY_RANK[p.severity or "info"] >= floor
            and (not p.trusted or p.malware_count)
        ]

    def block_targets(self, keys: Optional[list[str]] = None, min_severity: str = "low") -> list[BlockTarget]:
        """Blockable endpoints for the given apps (default: every culprit), noisiest first."""
        wanted = set(keys) if keys is not None else {p.app for p in self.culprits(min_severity)}
        targets = []
        for proc in self.processes():
            app = self.apps.get(proc.app)
            if proc.app not in wanted or app is None:
                continue
            f = self.facts(proc.app)
            targets.append(BlockTarget(
                name=app.name,
                exe=app.exe,
                tracker_domains=set(f.tracker_hosts),
                suspicious={ip: f.suspicious_hosts.get(ip) for ip in f.suspicious},
                orgs={ip: f.suspicious_orgs.get(ip) for ip in f.suspicious},
            ))
        return targets

    def totals(self) -> dict[str, set]:
        """Distinct trackers / countries / suspicious IPs / malware across untrusted apps
        (malware counts even for trusted apps — trust never hides it)."""
        out = {"trackers": set(), "countries": set(), "suspicious": set(), "malware": set()}
        for key in self.apps:
            f = self.facts(key)
            out["malware"].update(f.malware)
            if self.is_trusted(key):
                continue
            out["trackers"].update(f.trackers)
            out["countries"].update(f.countries)
            out["suspicious"].update(ip for ip, kind in f.suspicious.items() if kind != "known_malware")
        return out

    def app_for_pid(self, pid: int) -> Optional[str]:
        return next((key for key, app in self.apps.items() if app.pid == pid), None)
