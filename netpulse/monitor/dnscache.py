"""OS DNS-cache reader: recovers the hostname an app actually resolved (e.g. `doubleclick.net`),
which reverse-DNS can't (it returns `*.1e100.net`). Primary IP->hostname source on Windows.

Reads `ipconfig /displaydns` — the system resolver's own cache, no capture, no admin. Parsing is
positional (name, type, ..., data per record) so it doesn't depend on the Windows display language.
Mappings are remembered after the OS evicts them (tracker TTLs can be single-digit seconds), and
each (name, ip) remembers when it was last looked up so a shared IP (Google, CDNs) resolves to
the name queried most recently.

Caveat: apps with their own resolver (Chrome/Edge built-in DNS client, DoH) bypass this cache.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
import sys
import time
from collections import OrderedDict
from typing import Optional

log = logging.getLogger(__name__)

REFRESH_INTERVAL = 3.0
MIN_FORCED_GAP = 1.0  # at most one on-demand refresh per second
MAX_IPS = 20000
MAX_SEEN_NAMES = 50000

TYPE_A, TYPE_CNAME, TYPE_AAAA = 1, 5, 28
_KV = re.compile(r"^\s*\S.*?\s:\s(.*?)\s*$")


def parse_displaydns(text: str) -> list[tuple[str, int, int, str]]:
    """-> [(record_name, type, ttl, data)] for A/AAAA/CNAME records."""
    records = []
    block: list[str] = []
    for line in text.splitlines() + [""]:
        m = _KV.match(line)
        if m:
            block.append(m.group(1))
            continue
        if len(block) >= 4:
            try:
                rtype, ttl = int(block[1]), int(block[2])
            except ValueError:
                rtype, ttl = -1, 0
            if rtype in (TYPE_A, TYPE_AAAA, TYPE_CNAME):
                records.append((block[0].lower().rstrip("."), rtype, ttl, block[-1].lower().rstrip(".")))
        block = []
    return records


class DnsCache:
    def __init__(self, refresh_interval: float = REFRESH_INTERVAL):
        self.refresh_interval = refresh_interval
        self.available = sys.platform == "win32"
        # ip -> {name: last_looked_up_ts}; names include the full CNAME chain (query name first).
        self._names_by_ip: OrderedDict[str, dict[str, float]] = OrderedDict()
        self._ttl_seen: dict[tuple[str, str], int] = {}
        self.seen_names: OrderedDict[str, float] = OrderedDict()  # every A/AAAA/CNAME name ever cached
        self.version = 0
        self._lock = asyncio.Lock()
        self._last_refresh = 0.0

    # ---- reading ---------------------------------------------------------

    def _read(self) -> Optional[str]:
        try:
            out = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return out.stdout.decode("utf-8", errors="replace")
        except Exception:
            log.debug("ipconfig /displaydns failed", exc_info=True)
            return None

    def _ingest(self, records: list[tuple[str, int, int, str]], now: float) -> None:
        cname_parents: dict[str, set[str]] = {}
        addresses: list[tuple[str, int, str]] = []
        for name, rtype, ttl, data in records:
            self.seen_names[name] = now
            self.seen_names.move_to_end(name)
            if rtype == TYPE_CNAME:
                cname_parents.setdefault(data, set()).add(name)
                self.seen_names[data] = now
            else:
                addresses.append((name, ttl, data))

        for name, ttl, ip in addresses:
            chain = [name]
            frontier = [name]
            while frontier:  # walk CNAMEs back up to the name the app queried
                for parent in cname_parents.get(frontier.pop(), ()):
                    if parent not in chain:
                        chain.insert(0, parent)
                        frontier.append(parent)
            entry = self._names_by_ip.setdefault(ip, {})
            self._names_by_ip.move_to_end(ip)
            for n in chain:
                key = (n, ip)
                prev_ttl = self._ttl_seen.get(key)
                # New, or TTL went *up* since last read => it was looked up again just now.
                if prev_ttl is None or ttl > prev_ttl:
                    entry[n] = now
                else:
                    entry.setdefault(n, now)
                self._ttl_seen[key] = ttl

        while len(self._names_by_ip) > MAX_IPS:
            ip, names = self._names_by_ip.popitem(last=False)
            for n in names:
                self._ttl_seen.pop((n, ip), None)
        while len(self.seen_names) > MAX_SEEN_NAMES:
            self.seen_names.popitem(last=False)

    async def refresh(self, force: bool = False) -> bool:
        if not self.available:
            return False
        async with self._lock:
            now = time.time()
            if force and now - self._last_refresh < MIN_FORCED_GAP:
                return False
            text = await asyncio.to_thread(self._read)
            self._last_refresh = time.time()
            if text is None:
                return False
            self._ingest(parse_displaydns(text), self._last_refresh)
            self.version += 1
            return True

    async def run(self) -> None:
        if not self.available:
            log.info("DNS cache reader unavailable on %s; using reverse DNS only", sys.platform)
            return
        while True:
            try:
                await self.refresh()
            except Exception:
                log.exception("DNS cache refresh failed; continuing")
            await asyncio.sleep(self.refresh_interval)

    # ---- lookups ---------------------------------------------------------

    def names_for(self, ip: str) -> list[str]:
        """All names that resolved to ip, most recently looked-up first."""
        entry = self._names_by_ip.get(ip)
        if not entry:
            return []
        return sorted(entry, key=entry.get, reverse=True)

    def best_name(self, ip: str, when: Optional[float] = None) -> Optional[str]:
        """The name most likely behind a connection to ip opened at `when`: the most recent
        lookup at or before then (small slack for cache-read lag), else the most recent overall."""
        entry = self._names_by_ip.get(ip)
        if not entry:
            return None
        if when is not None:
            before = {n: t for n, t in entry.items() if t <= when + REFRESH_INTERVAL + 1}
            if before:
                entry = before
        # Prefer the query name over CNAME targets when lookup times tie (query name comes first).
        return max(entry, key=lambda n: (entry[n], -list(entry).index(n)))

    def chain_for(self, ip: str, name: str) -> list[str]:
        """Names looked up together with `name` for ip (its CNAME chain) — catches CNAME-cloaked trackers."""
        entry = self._names_by_ip.get(ip, {})
        ts = entry.get(name)
        return [n for n, t in entry.items() if t == ts] if ts is not None else [name]
