"""Live end-to-end runs against real connections: a probe process contacts trackers and beacons
to example.com while the real collector watches. Needs internet and the OS DNS cache, so these
are skipped by default — run them with `pytest -m live`.

Tracker domains blocked in your own hosts file will make these fail (the probe can't connect)."""

import asyncio
import socket
import subprocess
import sys
import time

import pytest

from netpulse.action.block import generate
from netpulse.alerts import Alerter
from netpulse.pipeline import Pipeline

from conftest import PROBE

pytestmark = pytest.mark.live


async def watch_probe(p: Pipeline, settle: float = 4) -> None:
    task = asyncio.create_task(p.run())
    await asyncio.sleep(2)
    probe = subprocess.Popen([sys.executable, str(PROBE)], stdout=subprocess.DEVNULL)
    while probe.poll() is None:
        await asyncio.sleep(1)
    await asyncio.sleep(settle)
    task.cancel()


def probe_culprit(p: Pipeline):
    return next((c for c in p.ranker.culprits() if c.name.startswith("python")), None)


def test_probe_is_caught_with_trackers_and_beacon():
    p = Pipeline(interval=1.0)
    asyncio.run(watch_probe(p))
    c = probe_culprit(p)
    assert c is not None and c.tracker_count >= 4, p.ranker.culprits()
    assert "beaconing" in c.verdict_text
    assert "0.0.0.0 www.google-analytics.com" in generate(p.ranker.block_targets([c.app]), "hosts").text


def test_malware_contact_goes_critical():
    # example.com is treated as malware for this run only - no real malware is contacted.
    p = Pipeline(interval=1.0)
    p.threats.domains["example.com"] = "urlhaus"
    asyncio.run(watch_probe(p, settle=3))
    c = next((c for c in p.ranker.culprits() if c.malware_count), None)
    assert c is not None and c.severity == "critical"
    assert c.malware[0].startswith("example.com")
    assert p.stats()["malware"] >= 1
    targets = p.ranker.block_targets([c.app])
    fw = generate(targets, "windows_fw").text
    assert "0.0.0.0 example.com" in generate(targets, "hosts").text
    ex_ips = {a[4][0] for a in socket.getaddrinfo("example.com", 443, socket.AF_INET)}
    assert not any(f"-RemoteAddress {ip}" in fw for ip in ex_ips)  # shared-CDN IP left to the hosts file


def test_probe_alerts_are_batched():
    sent = []
    p = Pipeline(interval=1.0, alerter=Alerter(sender=lambda t, b, url=None: sent.append((t, b)) or True,
                                               warmup=0, batch_seconds=3, cooldown=8))
    asyncio.run(watch_probe(p, settle=12))
    bodies = " | ".join(b for t, b in sent if "python" in t)
    assert "new tracker" in bodies
    assert "started beaconing to example.com" in bodies
    assert len([t for t, _ in sent if "python" in t]) <= 6


@pytest.mark.skipif(sys.platform != "win32", reason="reads the Windows DNS cache")
def test_dns_cache_lookup_of_malware_domain_alarms():
    async def go():
        p = Pipeline(interval=1.0)
        task = asyncio.create_task(p.run())
        await asyncio.sleep(2)
        p.threats.domains["evil-test.invalid"] = "hagezi"
        p.dns_cache._ingest([("evil-test.invalid", 1, 60, "203.0.113.50")], time.time())
        p.dns_cache.version += 1
        await asyncio.sleep(1.5)
        task.cancel()
        return p.unattributed_malware_lookups()
    assert any(h.startswith("evil-test.invalid") for h in asyncio.run(go()))
