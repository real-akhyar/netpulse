"""IP -> hostname (SPEC §1.2). DNS cache first (the name the app actually asked for), then
bounded/cached reverse-DNS as fallback. Never blocks the event loop; failures resolve to None."""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from netpulse.monitor.dnscache import DnsCache

log = logging.getLogger(__name__)

RDNS_CONCURRENCY = 64
RDNS_TIMEOUT = 1.0
RDNS_CACHE_SIZE = 4096

# Minimal multi-part public suffixes so eTLD+1 is right for common ccTLDs (MVP stand-in for the PSL).
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ne.kr",
    "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "net.hk", "org.hk", "com.sg", "net.sg", "org.sg", "edu.sg", "com.tw", "net.tw", "org.tw",
    "co.in", "net.in", "org.in", "ac.in", "gov.in", "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.mx", "org.mx", "co.za", "org.za", "com.tr", "net.tr", "org.tr", "com.ar", "com.co",
    "co.id", "or.id", "ac.id", "com.my", "net.my", "com.ph", "com.vn", "com.sa", "com.eg", "co.il", "org.il",
    "com.ua", "com.pl", "co.th", "in.th", "com.ng", "co.ke",
}


def registrable_domain(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@dataclass
class Resolution:
    host: Optional[str] = None
    source: Optional[str] = None  # "dns_cache" | "rdns" | None
    names: list[str] = field(default_factory=list)  # host plus CNAME chain, for tracker matching
    definitive: bool = True  # False if rDNS timed out/failed — a missing host then proves nothing


class Resolver:
    def __init__(self, dns_cache: Optional[DnsCache] = None):
        self.dns_cache = dns_cache or DnsCache()
        self._sem = asyncio.Semaphore(RDNS_CONCURRENCY)
        self._pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="rdns")
        self._rdns: OrderedDict[str, Optional[str]] = OrderedDict()
        self._inflight: dict[str, asyncio.Future] = {}

    def from_cache(self, ip: str, when: Optional[float] = None) -> Optional[Resolution]:
        name = self.dns_cache.best_name(ip, when)
        if name is None:
            return None
        return Resolution(host=name, source="dns_cache", names=self.dns_cache.chain_for(ip, name))

    async def resolve(self, ip: str, when: Optional[float] = None) -> Resolution:
        try:
            hit = self.from_cache(ip, when)
            if hit is None and self.dns_cache.available:
                # The connection was probably seen before the cache was last read — read it now.
                await self.dns_cache.refresh(force=True)
                hit = self.from_cache(ip, when)
            if hit is not None:
                return hit
            host, definitive = await self.reverse(ip)
            return Resolution(
                host=host, source="rdns" if host else None, names=[host] if host else [], definitive=definitive
            )
        except Exception:
            log.debug("resolve %s failed", ip, exc_info=True)
            return Resolution(definitive=False)

    async def reverse(self, ip: str) -> tuple[Optional[str], bool]:
        """-> (hostname or None, definitive). Not definitive = timed out / server failure."""
        if ip in self._rdns:
            self._rdns.move_to_end(ip)
            return self._rdns[ip]
        pending = self._inflight.get(ip)
        if pending is not None:
            return await asyncio.shield(pending)
        fut = asyncio.get_running_loop().create_future()
        self._inflight[ip] = fut
        result: tuple[Optional[str], bool] = (None, False)
        try:
            async with self._sem:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(loop.run_in_executor(self._pool, _gethostbyaddr, ip), RDNS_TIMEOUT)
        except (asyncio.TimeoutError, Exception):
            result = (None, False)
        finally:
            self._rdns[ip] = result
            while len(self._rdns) > RDNS_CACHE_SIZE:
                self._rdns.popitem(last=False)
            self._inflight.pop(ip, None)
            fut.set_result(result)
        return result


# h_errno / WSA codes meaning "the name really doesn't exist" (vs. try-again / server failure).
_NO_PTR_ERRNOS = {1, 4, 11001, 11004}  # HOST_NOT_FOUND, NO_DATA, WSAHOST_NOT_FOUND, WSANO_DATA


def _gethostbyaddr(ip: str) -> tuple[Optional[str], bool]:
    try:
        name = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
        return (name if name and name != ip else None), True
    except socket.herror as e:
        return None, e.errno in _NO_PTR_ERRNOS
    except (OSError, UnicodeError):
        return None, False
