"""Saved history: culprits survive a restart, the timeline records first-time findings, retention."""

import sqlite3
import time

import pytest

from netpulse.action.block import generate
from netpulse.models import ProcessInfo
from netpulse.pipeline import Pipeline
from netpulse.store import HistoryStore

from conftest import feed, make_conn

APP = r"C:\Python\python.exe"
TRACKERS = ["www.google-analytics.com", "stats.g.doubleclick.net", "sb.scorecardresearch.com", "cdn.segment.com"]


def nosy_run(p: Pipeline) -> None:
    """What the live probe does: a few trackers, then a 6-second beacon to example.com."""
    for i, host in enumerate(TRACKERS):
        feed(p, make_conn(i, APP, f"93.184.{i}.10", host))
    now = time.time()
    feed(p, make_conn(99, APP, "93.184.215.14", "example.com"), arrivals=[now - 30 + 6 * k for k in range(6)])
    p._on_info(APP, ProcessInfo(pid=10, exe=APP, signature="valid", signer="Python Software Foundation"))


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "history.db"
    store = HistoryStore(path)
    p = Pipeline(interval=1.0, history=store)
    assert p.restored == 0
    nosy_run(p)
    store.flush()
    return path, p


def culprit(p):
    return next((c for c in p.ranker.culprits() if c.name == "python.exe"), None)


def test_run_catches_trackers_and_beacon(db):
    _, p = db
    c = culprit(p)
    assert c is not None and c.tracker_count >= 4
    assert "beaconing" in c.verdict_text


def test_culprit_survives_restart(db):
    path, p = db
    before = culprit(p)
    p2 = Pipeline(interval=1.0, history=HistoryStore(path))  # brand-new pipeline, no traffic
    after = culprit(p2)
    assert p2.restored > 0 and after is not None
    assert set(after.top_trackers) == set(before.top_trackers)
    assert "beaconing" in after.verdict_text
    assert after.info is not None and after.info.signer == "Python Software Foundation"
    assert 0 < after.last_seen <= time.time()
    hosts = generate(p2.ranker.block_targets([after.app]), "hosts").text
    assert "0.0.0.0 www.google-analytics.com" in hosts


def test_timeline_records_findings_once(db):
    path, _ = db
    store = HistoryStore(path)
    events = store.timeline()
    kinds = {e["kind"] for e in events}
    assert {"tracker_contact", "beaconing", "first_online"} <= kinds
    assert all(e["severity"] != "info" for e in store.timeline(min_severity={"low", "medium", "high", "critical"}))
    rows = [(e["app"], e["key"]) for e in events if e["kind"] == "tracker_contact"]
    assert len(rows) == len(set(rows))


def test_retention_prunes_old_rows(db):
    path, _ = db
    old = time.time() - 40 * 86400
    with sqlite3.connect(path) as raw:
        raw.execute("INSERT INTO findings VALUES ('x','tracker_contact','old.example','x.exe','medium','old','',NULL,?,?,1)",
                    (old, old))
    assert not [e for e in HistoryStore(path).timeline(since=0) if e["key"] == "old.example"]


def test_clear_findings_and_activity(db):
    path, _ = db
    store = HistoryStore(path)
    store.clear_findings()
    assert store.timeline() == [] and store.apps()
    store.clear_activity()
    assert store.apps() == {} and store.endpoints() == []
    assert Pipeline(interval=1.0, history=HistoryStore(path)).restored == 0


def test_no_history_pipeline_starts_clean():
    p = Pipeline(interval=1.0)
    assert p.history is None and p.restored == 0 and not p.ranker.apps
