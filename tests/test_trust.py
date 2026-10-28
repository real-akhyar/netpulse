"""Trust list: matching, persistence, and how trust folds into ranking (reversibly, never hiding malware)."""

import json

from netpulse.action.block import generate
from netpulse.detect.rank import Ranker
from netpulse.models import Flag, ProcessInfo
from netpulse.trust import Trust, TrustStore

from conftest import TRACKER, make_conn

SP = r"C:\Apps\spotify.exe"
EVIL = r"C:\Users\x\AppData\Local\Temp\upd\svchost.exe"


def test_domain_covers_subdomains_not_lookalikes():
    t = Trust(domains={"doubleclick.net"})
    assert t.covers("doubleclick.net") and t.covers("stats.g.doubleclick.net")
    assert not t.covers("notdoubleclick.net") and not t.covers("doubleclick.net.evil.com")


def test_persistence(tmp_path):
    path = tmp_path / "trust.json"
    s = TrustStore(path)
    s.add("domain", "doubleclick.net")
    s.add("app", SP, "spotify.exe")
    s2 = TrustStore(path)
    assert s2.trust.domains == {"doubleclick.net"} and s2.trust.apps == {SP}
    assert json.loads(path.read_text())["rules"]
    assert s2.remove("domain", "doubleclick.net")
    assert "doubleclick.net" not in TrustStore(path).trust.domains
    s2.clear()
    assert TrustStore(path).rules() == []


def test_corrupt_file_starts_empty(tmp_path):
    path = tmp_path / "trust.json"
    path.write_text("{not json")
    assert TrustStore(path).rules() == []


def ranker_with_spotify():
    trust = Trust()
    r = Ranker(trust)
    r.observe(make_conn(1, SP, "1.1.1.1", "stats.g.doubleclick.net", "g.doubleclick.net", flags=[TRACKER]))
    r.observe(make_conn(2, SP, "2.2.2.2", "www.google-analytics.com", "google-analytics.com", flags=[TRACKER]))
    return trust, r


def agg(r, app=SP):
    return next(p for p in r.processes() if p.app == app)


def test_trusting_a_domain_is_reversible():
    trust, r = ranker_with_spotify()
    assert agg(r).tracker_count == 2 and r.culprits()
    trust.domains.add("doubleclick.net")
    assert agg(r).tracker_count == 1 and agg(r).top_trackers == ["google-analytics.com"]
    hosts = generate(r.block_targets([SP]), "hosts").text
    assert "doubleclick" not in hosts and "google-analytics" in hosts
    trust.domains.discard("doubleclick.net")
    assert agg(r).tracker_count == 2


def test_trusted_app_leaves_caught_and_exports():
    trust, r = ranker_with_spotify()
    trust.apps.add(SP)
    assert not r.culprits() and agg(r).trusted
    assert r.block_targets() == []
    assert not r.totals()["trackers"]


def test_trust_never_hides_malware():
    trust, r = ranker_with_spotify()
    r.observe(make_conn(3, EVIL, "50.16.16.211", threat="50.16.16.211",
                        flags=[Flag(id="known_malware", severity="critical", title="m")]))
    r.set_info(EVIL, ProcessInfo(pid=11, exe=EVIL, signature="valid", signer="X", parent_name="explorer.exe", parent_pid=1))
    trust.apps.add(EVIL)
    evil = agg(r, EVIL)
    assert evil in r.culprits() and evil.malware_count == 1
    assert r.totals()["malware"] == {"50.16.16.211"}
    assert r.process_alert(EVIL) is None  # but its process alert no longer paints its traffic
    trust.apps.discard(EVIL)
    assert r.process_alert(EVIL).id == "masquerading"
