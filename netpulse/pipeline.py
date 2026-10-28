"""Orchestration shared by headless mode and the server: monitor -> resolve + GeoIP -> detect -> rank.

Connections are enriched in place (the monitor's registry holds the same objects), and every
change is re-emitted as a SPEC §4 event on `out` when a consumer (the server) provides one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Optional

from netpulse.detect.heuristics import beacon_period, categorize, connection_flags
from netpulse.detect.rank import Ranker
from netpulse.detect.threats import ThreatIntel
from netpulse.detect.trackers import TrackerList
from netpulse.models import Connection, Flag, ProcessInfo
from netpulse.monitor.connections import ConnectionMonitor
from netpulse.monitor.dnscache import DnsCache
from netpulse.monitor.geoip import GeoIP
from netpulse.monitor.procinfo import ProcessInspector
from netpulse.monitor.resolve import Resolution, Resolver, registrable_domain
from netpulse.store import HistoryStore
from netpulse.trust import TrustStore

log = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, interval: float = 2.0, out: Optional[asyncio.Queue] = None,
                 history: Optional[HistoryStore] = None, trust: Optional[TrustStore] = None):
        self.history = history
        self.trust_store = trust
        self.restored = 0  # endpoints replayed from history at startup
        self._known_apps: set[str] = set()  # apps history has seen online before
        self._monitor_events: asyncio.Queue = asyncio.Queue()
        self.monitor = ConnectionMonitor(interval=interval, queue=self._monitor_events)
        self.dns_cache = DnsCache()
        self.resolver = Resolver(self.dns_cache)
        self.geo = GeoIP()
        self.trackers = TrackerList()
        self.threats = ThreatIntel()
        self.ranker = Ranker(trust.trust if trust else None)
        self.inspector = ProcessInspector()
        self._inspected_pids: set[int] = set()
        self.out = out
        self._host_source: dict[str, Optional[str]] = {}  # connection id -> "dns_cache" | "rdns" | None
        self._definitive: dict[str, bool] = {}  # connection id -> was the hostname lookup conclusive
        self._tasks: set[asyncio.Task] = set()
        # Tracker / malware domains seen in the OS DNS cache, whether or not we caught the connection.
        self.cache_tracker_hits: dict[str, float] = {}
        self.cache_malware_hits: dict[str, str] = {}  # indicator -> description
        self._cache_scanned_version = 0
        self._cache_scanned_ts = 0.0
        if history is not None:
            self._restore()

    async def run(self) -> None:
        await asyncio.gather(self.monitor.run(), self.dns_cache.run(), self._consume(), self._cache_watch())

    # ---- history ---------------------------------------------------------

    def _restore(self) -> None:
        """Replay saved endpoints into the ranker so culprits, verdicts and block targets come back
        exactly as they were computed, then re-attach saved process details."""
        try:
            apps = self.history.apps()
            self._known_apps = set(apps)
            for row in self.history.endpoints():
                conn = Connection(
                    id=f"history|{row['app']}|{row['ip']}|{row['port']}",
                    process_name=row["name"] or "unknown", process_exe=row["exe"], laddr="", lport=0,
                    raddr=row["ip"], rport=row["port"], status="CLOSED", scope="public",
                    remote_host=row["host"], country=row["country"], org=row["org"], lat=row["lat"], lon=row["lon"],
                    category=row["category"], tracker_rule=row["tracker_rule"],
                    threat_indicator=row["threat_indicator"], threat=row["threat"],
                    flags=[Flag(**f) for f in json.loads(row["flags"] or "[]")],
                    first_seen=row["first_seen"], last_seen=row["last_seen"], hit_count=row["hits"],
                )
                self.ranker.observe(conn, row["beacon_period"])
                self.restored += 1
            for key, row in apps.items():
                if row["info"] and key in self.ranker.apps:
                    self.ranker.set_info(key, ProcessInfo(**json.loads(row["info"])))
        except Exception:
            log.exception("restoring history failed; starting fresh")

    def _remember(self, conn: Connection, period: Optional[float]) -> None:
        """Save a classified public connection: its endpoint row, its findings, and the app."""
        now = conn.last_seen
        self.history.record_app(conn.app, conn.process_name, conn.process_exe, None, now)
        if conn.app not in self._known_apps:
            self._known_apps.add(conn.app)
            self.history.record_finding(conn.app, "first_online", conn.app, conn.process_name, "info",
                                        f"{conn.process_name} went online for the first time",
                                        conn.process_exe or "", conn.remote_host or conn.raddr, now)
        self.history.record_endpoint({
            "app": conn.app, "ip": conn.raddr, "port": conn.rport, "host": conn.remote_host,
            "category": conn.category, "country": conn.country, "org": conn.org, "lat": conn.lat, "lon": conn.lon,
            "tracker_rule": conn.tracker_rule, "threat_indicator": conn.threat_indicator, "threat": conn.threat,
            "flags": json.dumps([f.model_dump() for f in conn.flags]), "beacon_period": period,
            "name": conn.process_name, "exe": conn.process_exe, "ts": now,
        })
        remote = conn.remote_host or conn.raddr
        keys = {"tracker_contact": conn.tracker_rule, "known_malware": conn.threat_indicator,
                "beaconing": conn.raddr, "raw_ip": conn.raddr}
        for flag in conn.flags:
            if flag.id in keys and keys[flag.id]:
                self.history.record_finding(conn.app, flag.id, keys[flag.id], conn.process_name, flag.severity,
                                            flag.title, flag.detail, remote, now)

    def _remember_app(self, app: str, info: ProcessInfo) -> None:
        """Save process details and any app-level alerts (fake system file, cmd.exe online...)."""
        name = self.ranker.apps[app].name if app in self.ranker.apps else app
        now = time.time()
        self.history.record_app(app, name, info.exe, info.model_dump(), now)
        for flag in self.ranker.app_flags(app):
            if flag.id != "many_trackers" and flag.severity != "info":
                self.history.record_finding(app, flag.id, app, name, flag.severity, flag.title, flag.detail, None, now)

    # ---- events ----------------------------------------------------------

    def _emit(self, event: dict) -> None:
        if self.out is not None:
            self.out.put_nowait(event)

    async def _consume(self) -> None:
        while True:
            event = await self._monitor_events.get()
            try:
                kind = event["type"]
                if kind == "connection_new":
                    conn: Connection = event["connection"]
                    self._enrich_static(conn)
                    self._emit(event)
                    if conn.scope == "public":
                        self._spawn(self._resolve_and_detect(conn))
                    else:
                        self._observe(conn)
                elif kind == "connection_update":
                    self._observe(event["connection"])
                    self._emit(event)
                elif kind == "connection_closed":
                    self._host_source.pop(event["id"], None)
                    self._definitive.pop(event["id"], None)
                    self._emit(event)
            except Exception:
                log.exception("enrichment failed for event %s; continuing", event.get("type"))

    # ---- enrichment ------------------------------------------------------

    def _observe(self, conn: Connection, period: Optional[float] = None) -> None:
        # Ownerless sockets (closed before any poll saw them alive) are still listed, but can't be
        # pinned on an app — ranking them would put an unactionable "unknown" in the Caught panel.
        if conn.pid is not None:
            self.ranker.observe(conn, period)
            if conn.pid not in self._inspected_pids:
                self._inspected_pids.add(conn.pid)
                self._spawn(self._inspect(conn.pid, conn.app))

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _inspect(self, pid: int, app: str) -> None:
        try:
            await self.inspector.inspect(pid, on_update=lambda info: self._on_info(app, info))
        except Exception:
            log.debug("process inspection failed for pid %s", pid, exc_info=True)

    def _enrich_static(self, conn: Connection) -> None:
        if conn.scope != "public":
            conn.category = "local"
            return
        geo = self.geo.lookup(conn.raddr)
        conn.country, conn.city, conn.lat, conn.lon, conn.org = geo.country, geo.city, geo.lat, geo.lon, geo.org

    async def _resolve_and_detect(self, conn: Connection) -> None:
        try:
            res = await self.resolver.resolve(conn.raddr, conn.first_seen)
            self._apply(conn, res)
        except Exception:
            log.exception("resolve/detect failed for %s", conn.raddr)

    def _apply(self, conn: Connection, res: Resolution) -> None:
        self._host_source[conn.id] = res.source
        self._definitive[conn.id] = res.definitive
        conn.remote_host = res.host
        conn.remote_domain = registrable_domain(res.host)
        conn.tracker_rule = self.trackers.match_any(res.names)
        hit = self.threats.match(conn.raddr, res.names)
        conn.threat_indicator = hit.indicator if hit else None
        conn.threat = hit.describe() if hit else None
        self._classify(conn)

    def _classify(self, conn: Connection) -> None:
        """Flags + category for a resolved public connection, then rank and emit it."""
        arrivals = self.monitor.flow_arrivals(conn.app, conn.raddr, conn.rport)
        conn.flags = connection_flags(conn, arrivals, resolved=self._definitive.get(conn.id, True))
        if conn.threat_indicator:
            host = conn.remote_host or conn.raddr
            conn.flags.insert(0, Flag(
                id="known_malware", severity="critical",
                title=f"Known malware server: {conn.threat_indicator}",
                detail=f"{conn.process_name} connected to {host}, which is {conn.threat}.",
            ))
        alert = self.ranker.process_alert(conn.app)
        if alert is not None:
            # A flagged app (fake system file, cmd.exe online...) makes all its traffic suspicious.
            conn.flags.append(Flag(id="suspicious_process", severity=alert.severity, title=alert.title, detail=alert.detail))
        conn.category = categorize(conn)
        # History is kept even if the socket already closed — a culprit stays caught.
        period = beacon_period(arrivals)
        self._observe(conn, period)  # ranker + history get the untrusted findings, so trust stays reversible
        if self.history is not None and conn.pid is not None:
            self._remember(conn, period)
        self._apply_trust(conn)
        if conn.id in self.monitor.connections:
            self._emit({"type": "connection_update", "connection": conn})

    def _apply_trust(self, conn: Connection) -> None:
        """What the user sees: a trusted domain, or a trusted app's traffic, shows as normal —
        except known malware, which an app's trust never hides."""
        trust = self.ranker.trust
        domain_trusted = trust.covers_any(conn.remote_host, conn.tracker_rule, conn.threat_indicator)
        app_trusted = conn.app in trust.apps and not conn.threat_indicator
        if not (domain_trusted or app_trusted) or conn.category == "normal":
            return
        what = f"{conn.remote_host or conn.raddr} is" if domain_trusted else f"{conn.process_name} is"
        conn.flags = [f for f in conn.flags if f.severity == "info"] + [
            Flag(id="trusted", severity="info", title="Trusted by you", detail=f"{what} on your trust list.")]
        conn.category = "normal"

    def reapply_trust(self) -> None:
        """After the trust list changes: re-check every open public connection. The ranker needs
        nothing — it folds trust in whenever it's asked."""
        for conn in list(self.monitor.connections.values()):
            if conn.scope == "public" and conn.id in self._host_source:
                self._classify(conn)

    def _on_info(self, app: str, info: ProcessInfo) -> None:
        """Process details arrive after the app's first connections: re-check those if the app
        turns out to be suspicious (no new DNS lookups — just flags and category)."""
        self.ranker.set_info(app, info)
        if self.history is not None and info.signature != "checking":
            self._remember_app(app, info)
        if self.ranker.process_alert(app) is None:
            return
        for conn in list(self.monitor.connections.values()):
            if conn.app == app and conn.scope == "public" and conn.id in self._host_source:
                self._classify(conn)

    async def _cache_watch(self) -> None:
        """After each DNS-cache read: upgrade connections that only had rDNS/no name, and scan
        newly cached names for trackers (catches lookups whose sockets we never saw)."""
        if not self.dns_cache.available:
            return
        while True:
            await asyncio.sleep(1.0)
            if self.dns_cache.version == self._cache_scanned_version:
                continue
            self._cache_scanned_version = self.dns_cache.version
            try:
                for conn in list(self.monitor.connections.values()):
                    if conn.scope != "public" or conn.id not in self._host_source:
                        continue
                    if self._host_source[conn.id] == "dns_cache":
                        continue
                    hit = self.resolver.from_cache(conn.raddr, conn.first_seen)
                    if hit is not None:
                        self._apply(conn, hit)
                newest = self._cache_scanned_ts
                for name, ts in self.dns_cache.seen_names.items():
                    if ts <= self._cache_scanned_ts:
                        continue
                    newest = max(newest, ts)
                    rule = self.trackers.match(name)
                    if rule and rule not in self.cache_tracker_hits:
                        self.cache_tracker_hits[rule] = ts
                    threat = self.threats.match_host(name)
                    if threat and threat.indicator not in self.cache_malware_hits:
                        self.cache_malware_hits[threat.indicator] = threat.describe()
                self._cache_scanned_ts = newest
            except Exception:
                log.exception("DNS cache scan failed; continuing")

    # ---- views -----------------------------------------------------------

    def _explained(self, attr: str) -> set[str]:
        """Every tracker rule / malware indicator some recorded connection accounts for."""
        return {v for app in self.ranker.apps.values() for ep in app.endpoints.values() if (v := getattr(ep, attr))}

    def unattributed_tracker_lookups(self) -> list[str]:
        """Tracker domains something on this machine looked up, but no caught connection explains."""
        explained = self._explained("tracker_rule")
        trust = self.ranker.trust
        return [d for d in self.cache_tracker_hits if d not in explained and not trust.covers(d)]

    def unattributed_malware_lookups(self) -> list[str]:
        """Known-malware domains looked up on this machine that no caught connection explains —
        the lookup alone is worth an alarm, even if the connection was too quick to see."""
        explained = self._explained("threat_indicator")
        trust = self.ranker.trust
        return [f"{d} — {desc}" for d, desc in self.cache_malware_hits.items()
                if d not in explained and not trust.covers(d)]

    def stats(self) -> dict:
        totals = self.ranker.totals()
        return {
            "apps": len(self.ranker.apps),
            "trackers": len(totals["trackers"]),
            "countries": len(totals["countries"]),
            "suspicious": len(totals["suspicious"]),
            "malware": len(totals["malware"]) + len(self.unattributed_malware_lookups()),
        }
