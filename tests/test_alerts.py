"""Desktop alerts: batching, immediacy for critical, dedupe, trust, warm-up, levels, caps, cooldown.
A fake sender stands in for the Windows toast."""

import asyncio
import time

from netpulse.alerts import Alert, Alerter
from netpulse.trust import Trust


class Fake:
    def __init__(self):
        self.sent = []

    def __call__(self, title, body, url=None):
        self.sent.append((time.time(), title, body))
        return True


def tracker(app, name, rule):
    return Alert(app, name, "tracker_contact", rule, "medium", f"Contacted ad/tracker domain {rule}", "d", rule)


def run(alerter, actions, wait):
    async def scenario():
        task = asyncio.create_task(alerter.run())
        t0 = time.time()
        actions()
        await asyncio.sleep(wait)
        task.cancel()
        return t0
    return asyncio.run(scenario())


def test_trackers_from_one_app_are_batched():
    f = Fake()
    a = Alerter(sender=f, warmup=0, batch_seconds=1)
    run(a, lambda: [a.submit(tracker("C:\\chrome.exe", "chrome.exe", f"t{i}.com")) for i in range(6)], 2.5)
    assert len(f.sent) == 1 and "contacted 6 new trackers" in f.sent[0][2]


def test_critical_is_immediate():
    f = Fake()
    a = Alerter(sender=f, warmup=0, batch_seconds=60)
    t0 = run(a, lambda: a.submit(Alert("C:\\x\\svchost.exe", "svchost.exe", "masquerading", "k", "critical",
                                       "Fake system file: svchost.exe outside the Windows folder", "detail")), 2.5)
    assert len(f.sent) == 1 and f.sent[0][0] - t0 < 2.2


def test_history_known_findings_are_old_news():
    f = Fake()
    a = Alerter(sender=f, warmup=0, batch_seconds=1)
    a.seed({("C:\\chrome.exe", "tracker_contact", "old.com")})
    run(a, lambda: [a.submit(tracker("C:\\chrome.exe", "chrome.exe", d)) for d in ("old.com", "new.com", "new.com")], 2.5)
    assert len(f.sent) == 1 and "new.com" in f.sent[0][2] and "old.com" not in f.sent[0][2]


def test_trust_silences_except_malware():
    f = Fake()
    a = Alerter(sender=f, trust=Trust(apps={"C:\\spotify.exe"}, domains={"doubleclick.net"}), warmup=0, batch_seconds=1)

    def actions():
        a.submit(tracker("C:\\spotify.exe", "spotify.exe", "x.com"))
        a.submit(tracker("C:\\chrome.exe", "chrome.exe", "stats.g.doubleclick.net"))
        a.submit(Alert("C:\\spotify.exe", "spotify.exe", "known_malware", "50.16.16.211", "critical", "Known malware server", "d"))
    run(a, actions, 2.5)
    assert len(f.sent) == 1 and "malware" in f.sent[0][1].lower()


def test_warmup_holds_back_first_online():
    f = Fake()
    a = Alerter(sender=f, warmup=60, batch_seconds=1)
    run(a, lambda: a.submit(Alert("C:\\a.exe", "a.exe", "first_online", "C:\\a.exe", "info", "t", "")), 2)
    assert f.sent == []


def test_levels():
    f = Fake()
    a = Alerter(level="critical", sender=f, warmup=0, batch_seconds=1)
    run(a, lambda: a.submit(tracker("C:\\c.exe", "c.exe", "t.com")), 2)
    assert f.sent == []
    a = Alerter(level="off", sender=f, warmup=0, batch_seconds=1)
    run(a, lambda: a.submit(Alert("C:\\m.exe", "m.exe", "known_malware", "i", "critical", "t", "d")), 2)
    assert f.sent == []


def test_batch_is_capped():
    f = Fake()
    a = Alerter(sender=f, warmup=0, batch_seconds=1)
    run(a, lambda: [a.submit(tracker(f"C:\\app{i}.exe", f"app{i}.exe", "t.com")) for i in range(7)], 2.5)
    assert len(f.sent) == 4 and "4 more apps" in f.sent[-1][1]


def test_per_app_cooldown():
    f = Fake()
    a = Alerter(sender=f, warmup=0, batch_seconds=1, cooldown=8)

    async def trickle():
        task = asyncio.create_task(a.run())
        for i in range(6):
            a.submit(tracker("C:\\chrome.exe", "chrome.exe", f"slow{i}.com"))
            await asyncio.sleep(1.2)
        await asyncio.sleep(4)
        task.cancel()
    asyncio.run(trickle())
    assert len(f.sent) == 2  # one ping now, one summary after the cooldown
