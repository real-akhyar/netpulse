"""psutil poll loop: this machine's own connections -> Connection records + diff events (SPEC §1.1).

Reads the OS connection table only — no packet capture. Never raises out of the loop:
a failing pid lookup degrades to process_name="unknown" and the connection is kept.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from collections import deque
from typing import NamedTuple, Optional

import psutil

from netpulse.models import Connection

log = logging.getLogger(__name__)

ARRIVAL_HISTORY = 32  # new-connection timestamps kept per flow, for beacon detection
FLOW_IDLE_PRUNE = 600.0  # forget a flow's arrival history after this long without a new connection

# Flow = (app, remote_ip, remote_port). Local port is deliberately excluded so that
# reconnects to the same endpoint count as repeated arrivals of one flow.
FlowKey = tuple[str, str, int]


class _Row(NamedTuple):
    """Minimal connection row for the per-process fallback (same fields we read from psutil.sconn)."""

    laddr: tuple
    raddr: tuple
    status: str
    pid: int


def classify_scope(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "private"
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.is_loopback:
        return "loopback"
    if addr.is_global:
        return "public"
    return "private"


class ConnectionMonitor:
    def __init__(self, interval: float = 2.0, queue: Optional[asyncio.Queue] = None):
        self.interval = interval
        self.queue = queue
        self.paused = False
        self.connections: dict[str, Connection] = {}
        self.arrivals: dict[FlowKey, deque[float]] = {}
        self.ticks = 0
        self._own_pid = os.getpid()
        self._proc_cache: dict[int, tuple[str, Optional[str]]] = {}
        # (lport, raddr, rport) -> owner seen while the socket was alive. Windows reassigns closing
        # sockets (TIME_WAIT) to pid 0; this lets them keep their real app instead of going "unknown".
        self._socket_owners: dict[tuple[int, str, int], tuple[int, str, Optional[str]]] = {}
        self._use_per_process = False  # set if the system-wide table is denied (e.g. macOS non-root)

    # ---- process mapping -------------------------------------------------

    def _process_info(self, pid: Optional[int]) -> tuple[str, Optional[str]]:
        # pid 0 on Windows is "System Idle Process", which owns lingering TIME_WAIT sockets —
        # attributing those to it would be misleading.
        if not pid:
            return "unknown", None
        cached = self._proc_cache.get(pid)
        if cached is not None:
            return cached
        name, exe = "unknown", None
        try:
            proc = psutil.Process(pid)
            name = proc.name() or "unknown"
            try:
                exe = proc.exe() or None
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = None
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            pass
        self._proc_cache[pid] = (name, exe)
        return name, exe

    # ---- snapshot (blocking; runs in a worker thread) --------------------

    def _raw_connections(self) -> list:
        if not self._use_per_process:
            try:
                return psutil.net_connections(kind="inet")
            except psutil.AccessDenied:
                log.warning("system-wide connection table denied; falling back to per-process scan")
                self._use_per_process = True
        rows = []
        for proc in psutil.process_iter():
            try:
                getter = getattr(proc, "net_connections", None) or proc.connections
                for c in getter(kind="inet"):
                    rows.append(_Row(c.laddr, c.raddr, c.status, proc.pid))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
        return rows

    def _snapshot(self) -> Optional[dict[str, Connection]]:
        now = time.time()
        try:
            raw = self._raw_connections()
        except Exception:
            log.exception("reading connection table failed")
            return None
        current: dict[str, Connection] = {}
        live_pids: set[int] = set()
        owners: dict[tuple[int, str, int], tuple[int, str, Optional[str]]] = {}
        for c in raw:
            try:
                if not c.raddr or c.pid == self._own_pid:
                    continue
                rip, rport = c.raddr.ip, c.raddr.port
                lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
                sock = (lport, rip, rport)
                if c.pid:
                    pid = c.pid
                    live_pids.add(pid)
                    name, exe = self._process_info(pid)
                    owners[sock] = (pid, name, exe)
                elif sock in self._socket_owners:
                    pid, name, exe = owners[sock] = self._socket_owners[sock]
                else:
                    pid, name, exe = None, "unknown", None
                key = f"{pid}|{rip}|{rport}|{lport}"
                if key in current:
                    continue
                current[key] = Connection(
                    id=key,
                    pid=pid,
                    process_name=name,
                    process_exe=exe,
                    laddr=lip,
                    lport=lport,
                    raddr=rip,
                    rport=rport,
                    status=c.status or "NONE",
                    scope=classify_scope(rip),
                    first_seen=now,
                    last_seen=now,
                )
            except Exception:
                log.debug("skipping malformed connection row %r", c, exc_info=True)
        self._socket_owners = owners
        # Drop cached process info for pids that no longer hold connections (guards pid reuse).
        for pid in list(self._proc_cache):
            if pid not in live_pids:
                del self._proc_cache[pid]
        return current

    # ---- diffing ---------------------------------------------------------

    def _diff(self, current: dict[str, Connection], now: float) -> list[dict]:
        events: list[dict] = []
        for key, fresh in current.items():
            old = self.connections.get(key)
            if old is None:
                self.connections[key] = fresh
                self._record_arrival(fresh, now)
                events.append({"type": "connection_new", "connection": fresh})
                continue
            old.last_seen = now
            old.hit_count += 1
            if old.status != fresh.status:
                old.status = fresh.status
                events.append({"type": "connection_update", "connection": old})
        for key in [k for k in self.connections if k not in current]:
            del self.connections[key]
            events.append({"type": "connection_closed", "id": key})
        self._prune_arrivals(now)
        return events

    def _record_arrival(self, conn: Connection, now: float) -> None:
        flow = (conn.app, conn.raddr, conn.rport)
        history = self.arrivals.get(flow)
        if history is None:
            history = self.arrivals[flow] = deque(maxlen=ARRIVAL_HISTORY)
        history.append(now)

    def _prune_arrivals(self, now: float) -> None:
        for flow in [f for f, h in self.arrivals.items() if now - h[-1] > FLOW_IDLE_PRUNE]:
            del self.arrivals[flow]

    def flow_arrivals(self, app: str, raddr: str, rport: int) -> list[float]:
        return list(self.arrivals.get((app, raddr, rport), ()))

    # ---- loop ------------------------------------------------------------

    async def tick(self) -> list[dict]:
        current = await asyncio.to_thread(self._snapshot)
        if current is None:
            return []
        self.ticks += 1
        events = self._diff(current, time.time())
        if self.queue is not None:
            for event in events:
                await self.queue.put(event)
        return events

    async def run(self) -> None:
        while True:
            if not self.paused:
                try:
                    await self.tick()
                except Exception:
                    log.exception("poll tick failed; continuing")
            await asyncio.sleep(self.interval)
