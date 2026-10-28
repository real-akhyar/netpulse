"""HTTP API: trust, export, one-click block (sandboxed), per-area reset, report page."""

import time

import pytest
from fastapi.testclient import TestClient

from netpulse.action.apply import BlockStore, read_managed_domains
from netpulse.models import Connection
from netpulse.report import report_since
from netpulse.server import create_app
from netpulse.store import HistoryStore
from netpulse.trust import TrustStore

from conftest import feed, make_conn, windows_only

APP = r"C:\Apps\nosy.exe"


@pytest.fixture
def stores(tmp_path, sandbox_hosts):
    import netpulse.action.apply as apply_mod
    return {
        "history": HistoryStore(tmp_path / "history.db"),
        "trust": TrustStore(tmp_path / "trust.json"),
        "blocks": BlockStore(tmp_path / "blocks.json", apply_mod.Applier(hosts=sandbox_hosts)),
    }


@pytest.fixture
def client(stores, monkeypatch):
    # Real processes on the machine get Authenticode-checked by PowerShell, which can take ~20s
    # and holds up shutdown. Not what these tests are about.
    monkeypatch.setattr("netpulse.monitor.procinfo.check_signatures", lambda paths: {})
    app = create_app(1.0, **stores)
    with TestClient(app) as c:
        p = app.state.hub.pipeline
        for i, host in enumerate(["www.google-analytics.com", "stats.g.doubleclick.net"]):
            feed(p, make_conn(i, APP, f"93.184.{i}.10", host, pid=4242))
        c.hub = app.state.hub
        yield c


def test_trust_api(client):
    assert client.post("/api/trust", json={"kind": "domain", "value": "bad domain; rm -rf"}).status_code == 400
    assert client.post("/api/trust", json={"kind": "app", "value": r"C:\never\seen.exe"}).status_code == 400
    r = client.post("/api/trust", json={"kind": "domain", "value": "Example.COM."})
    assert r.status_code == 200 and r.json()["rules"][0]["value"] == "example.com"
    r = client.post("/api/trust", json={"kind": "app", "value": APP, "name": "x\x07y"})
    assert r.status_code == 200 and any(rule["name"] == "xy" for rule in r.json()["rules"])
    assert client.post("/api/untrust", json={"kind": "domain", "value": "nope.example"}).status_code == 404
    r = client.post("/api/untrust", json={"kind": "domain", "value": "example.com"})
    assert r.status_code == 200 and not any(rule["value"] == "example.com" for rule in r.json()["rules"])


def test_export(client):
    r = client.post("/api/block", json={"apps": [APP], "format": "hosts"})
    assert r.status_code == 200 and "0.0.0.0 www.google-analytics.com" in r.json()["text"]
    assert client.post("/api/block", json={"format": "iptables"}).status_code == 422


@windows_only
def test_one_click_block_and_undo(client, sandbox_hosts):
    out = client.post("/api/blocks/apply", json={"apps": [APP]}).json()
    assert out["ok"], out
    assert "www.google-analytics.com" in read_managed_domains(sandbox_hosts)
    stats = client.hub.stats()["blocks"]
    assert stats["count"] == len(out["entries"]) and "nosy.exe" in stats["apps"]
    first = out["entries"][0]["id"]
    out = client.post("/api/blocks/undo", json={"ids": [first]}).json()
    assert out["ok"] and first not in {e["id"] for e in out["entries"]}
    assert client.post("/api/blocks/undo", json={}).status_code == 400
    out = client.post("/api/blocks/undo", json={"all": True}).json()
    assert out["ok"] and out["entries"] == [] and read_managed_domains(sandbox_hosts) == set()


def test_reset_each_area(client, stores):
    history, trust = stores["history"], stores["trust"]
    history.flush()
    assert history.timeline()
    assert client.post("/api/reset", json={"target": "timeline"}).status_code == 200
    assert history.timeline() == []

    assert history.apps() and APP in client.hub.pipeline.ranker.apps
    assert client.post("/api/reset", json={"target": "caught"}).status_code == 200
    assert history.apps() == {} and APP not in client.hub.pipeline.ranker.apps

    trust.add("domain", "doubleclick.net")
    assert client.post("/api/reset", json={"target": "trust"}).status_code == 200
    assert trust.rules() == []

    client.hub.recent_closed["x"] = (Connection.model_construct(id="x"), time.time())
    assert client.post("/api/reset", json={"target": "map"}).status_code == 200
    assert not client.hub.recent_closed

    assert report_since() is None
    assert client.post("/api/reset", json={"target": "report"}).status_code == 200
    assert abs(report_since() - time.time()) < 10

    assert client.post("/api/reset", json={"target": "everything"}).status_code == 422


def test_reset_timeline_without_history():
    with TestClient(create_app(1.0)) as c:
        assert c.post("/api/reset", json={"target": "timeline"}).status_code == 409


def test_report_page(client):
    r = client.get("/report")
    assert r.status_code == 200 and "privacy report" in r.text.lower() and "nosy.exe" in r.text
    r = client.get("/report?download=1")
    assert "attachment" in r.headers["content-disposition"]


def test_dashboard_and_websocket(client):
    assert "netpulse" in client.get("/").text
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"]
