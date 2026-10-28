"""The dashboard counts what's connected right now; the report counts everything caught."""

import time

import pytest
from fastapi.testclient import TestClient

from netpulse.models import Flag
from netpulse.pipeline import LIVE_GRACE, Pipeline
from netpulse.report import collect, render
from netpulse.server import create_app

from conftest import feed, make_conn

APP = r"C:\Apps\nosy.exe"


def online(p, conn, status="ESTABLISHED", age=0.0):
    """Put a fed connection into the monitor's table, as if the OS still listed it."""
    conn.status = status
    conn.first_seen = time.time() - age
    p.monitor.connections[conn.id] = conn
    return conn


@pytest.fixture
def pipeline():
    p = Pipeline(interval=1.0)
    p.tracker_now = feed(p, make_conn(1, APP, "93.184.1.10", "www.google-analytics.com"))
    p.tracker_gone = feed(p, make_conn(2, APP, "93.184.2.10", "stats.g.doubleclick.net"))
    return p


def test_live_endpoints_follow_the_connection_table(pipeline):
    p = pipeline
    assert p.live_endpoints() == {}
    online(p, p.tracker_now)
    assert p.live_endpoints() == {APP: {("93.184.1.10", 443)}}
    online(p, p.tracker_gone, status="TIME_WAIT", age=LIVE_GRACE + 5)  # closed a while ago
    assert p.live_endpoints() == {APP: {("93.184.1.10", 443)}}
    online(p, p.tracker_gone, status="TIME_WAIT", age=1)  # a quick ping just seen while closing
    assert ("93.184.2.10", 443) in p.live_endpoints()[APP]


def test_live_counts_only_whats_connected(pipeline):
    p = pipeline
    online(p, p.tracker_now)
    live = p.stats(live=True)
    assert live["trackers"] == 1 and live["apps"] == 1
    assert p.stats()["trackers"] == 2  # the session (and the report) keeps both
    (agg,) = [x for x in p.ranker.processes(p.live_endpoints()) if x.app == APP]
    assert agg.tracker_count == 1 and agg.top_trackers == ["google-analytics.com"]

    del p.monitor.connections[p.tracker_now.id]  # the tracker goes off
    assert p.stats(live=True)["trackers"] == 0
    assert not p.ranker.culprits(live=p.live_endpoints())
    assert p.ranker.culprits()  # still caught for the session


def test_report_counts_everything(pipeline):
    data = collect(pipeline)  # nothing is live, but both trackers were caught
    assert data.trackers == 2
    assert [c["name"] for c in data.culprits] == ["nosy.exe"]
    assert "last active" in render(data) and "active now" not in render(data)
    online(pipeline, pipeline.tracker_now)
    assert "active now" in render(collect(pipeline))


def test_known_malware_stays_until_cleared(pipeline):
    p = pipeline
    feed(p, make_conn(3, APP, "50.16.16.211"))  # Feodo-listed IP, not connected any more
    assert p.stats(live=True)["malware"] == 1
    (agg,) = p.ranker.culprits(live=p.live_endpoints())
    assert agg.malware_count == 1


def test_dns_lookups_age_out_of_the_live_view(pipeline):
    p = pipeline
    p.cache_tracker_hits["hotjar.com"] = time.time()
    p.cache_tracker_hits["criteo.com"] = time.time() - 3600
    assert p.unattributed_tracker_lookups(live=True) == ["hotjar.com"]
    assert set(p.unattributed_tracker_lookups()) == {"hotjar.com", "criteo.com"}
    p.reset("caught")
    assert p.unattributed_tracker_lookups() == []


def test_server_marks_active_and_earlier(monkeypatch):
    monkeypatch.setattr("netpulse.monitor.procinfo.check_signatures", lambda paths: {})
    app = create_app(1.0)
    hub = app.state.hub
    p = hub.pipeline
    monkeypatch.setattr(p.monitor, "_snapshot", lambda: None)  # never read the real table: ours is fake
    with TestClient(app) as client:
        conn = feed(p, make_conn(1, APP, "93.184.1.10", "www.google-analytics.com", pid=4242))
        feed(p, make_conn(2, APP, "93.184.2.10", "stats.g.doubleclick.net", pid=4242))
        online(p, conn)

        view = next(x for x in client.get("/api/processes").json() if x["app"] == APP)
        assert view["active"] and view["tracker_count"] == 1
        assert hub.stats()["trackers"] == 1

        del p.monitor.connections[conn.id]
        view = next(x for x in client.get("/api/processes").json() if x["app"] == APP)
        assert view["active"] is False and view["tracker_count"] == 2  # earlier: everything it did
        assert hub.stats()["trackers"] == 0
        assert "nosy.exe" in client.get("/report").text


def test_hosts_file_blocks_are_not_lookups():
    from netpulse.monitor.dnscache import TYPE_A, DnsCache
    d = DnsCache()
    d._ingest([("api.mixpanel.com", TYPE_A, 60, "0.0.0.0"), ("static.hotjar.com", TYPE_A, 60, "93.184.1.10")], time.time())
    assert set(d.seen_names) == {"static.hotjar.com"}
