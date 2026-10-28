"""Orchestration shared by headless mode and the server: monitor -> resolve + GeoIP -> detect -> rank.

Connections are enriched in place (the monitor's registry holds the same objects), and every
change is re-emitted as a SPEC §4 event on `out` when a consumer (the server) provides one.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from netpulse.detect.heuristics import beacon_period, categorize, connection_flags
from netpulse.detect.rank import Ranker
from netpulse.detect.trackers import TrackerList
from netpulse.models import Connection
from netpulse.monitor.connections import ConnectionMonitor
from netpulse.monitor.dnscache import DnsCache
from netpulse.monitor.geoip import GeoIP
from netpulse.monitor.resolve import Resolution, Resolver, registrable_domain

log = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, interval: float = 2.0, out: Optional[asyncio.Queue] = None):
        self._monitor_events: asyncio.Queue = asyncio.Queue()
        self.monitor = ConnectionMonitor(interval=interval, queue=self._monitor_events)
        self.dns_cache = DnsCache()
        self.resolver = Resolver(self.dns_cache)
        self.geo = GeoIP()
        self.trackers = TrackerList()
        self.ranker = Ranker()
        self.out = out
        self._host_source: dict[str, Optional[str]] = {}  # connection id -> "dns_cache" | "rdns" | None
        self._tasks: set[asyncio.Task] = set()
        # Tracker domains seen in the OS DNS cache, whether or not we caught the connection.
        self.cache_tracker_hits: dict[str, float] = {}
        self._cache_scanned_version = 0
        self._cache_scanned_ts = 0.0

    async def run(self) -> None:
        await asyncio.gather(self.monitor.run(), self.dns_cache.run(), self._consume(), self._cache_watch())

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
                        task = asyncio.create_task(self._resolve_and_detect(conn))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)
                    else:
                        self._observe(conn)
                elif kind == "connection_update":
                    self._observe(event["connection"])
                    self._emit(event)
                elif kind == "connection_closed":
                    self._host_source.pop(event["id"], None)
                    self._emit(event)
            except Exception:
                log.exception("enrichment failed for event %s; continuing", event.get("type"))

    # ---- enrichment ------------------------------------------------------

    def _observe(self, conn: Connection, period: Optional[float] = None) -> None:
        # Ownerless sockets (closed before any poll saw them alive) are still listed, but can't be
        # pinned on an app — ranking them would put an unactionable "unknown" in the Caught panel.
        if conn.pid is not None:
            self.ranker.observe(conn, period)

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
        conn.remote_host = res.host
        conn.remote_domain = registrable_domain(res.host)
        conn.tracker_rule = self.trackers.match_any(res.names)
        arrivals = self.monitor.flow_arrivals(conn.app, conn.raddr, conn.rport)
        conn.flags = connection_flags(conn, arrivals, resolved=res.definitive)
        conn.category = categorize(conn)
        # History is kept even if the socket already closed — a culprit stays caught.
        self._observe(conn, beacon_period(arrivals))
        if conn.id in self.monitor.connections:
            self._emit({"type": "connection_update", "connection": conn})

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
                self._cache_scanned_ts = newest
            except Exception:
                log.exception("DNS cache scan failed; continuing")

    # ---- views -----------------------------------------------------------

    def unattributed_tracker_lookups(self) -> list[str]:
        """Tracker domains something on this machine looked up, but no caught connection explains."""
        attributed = {rule for app in self.ranker.apps.values() for rule in app.trackers}
        return [d for d in self.cache_tracker_hits if d not in attributed]

    def stats(self) -> dict:
        apps = self.ranker.apps.values()
        return {
            "apps": len(self.ranker.apps),
            "trackers": len({rule for a in apps for rule in a.trackers}),
            "countries": len({c for a in apps for c in a.countries}),
            "suspicious": len({ip for a in apps for ip in a.suspicious}),
        }
