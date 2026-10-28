"""Privacy report card: grading, redaction, escaping, company buckets, report periods."""

import re
import time

import pytest

from netpulse.detect.companies import company_for
from netpulse.models import Connection, Flag, ProcessInfo
from netpulse.pipeline import Pipeline
from netpulse.report import ReportData, collect, grade, redact, render, report_since, set_report_since

from conftest import feed, make_conn


def rd(**kw):
    base = dict(generated=0, period_start=None, period_end=None, os_name="Windows", apps_watched=1, trusted_apps=0)
    return ReportData(**{**base, **kw})


@pytest.mark.parametrize("kw, expected", [
    ({}, "A"),
    ({"trackers": 4}, "A"),
    ({"trackers": 6}, "B"),
    ({"trackers": 15, "beacons": 1}, "C"),
    ({"critical_alert_apps": 1}, "D"),
    ({"malware": ["x - y"]}, "F"),
])
def test_grade(kw, expected):
    assert grade(rd(**kw))[1] == expected


def test_redaction():
    assert redact(r"runs from C:\Users\akhya\AppData\Local\Temp\x") == r"runs from C:\Users\…\AppData\Local\Temp\x"
    assert "Bob" not in redact(r"c:\users\Bob\Downloads")
    assert redact(r"C:\Program Files\App\a.exe") == r"C:\Program Files\App\a.exe"


def test_companies():
    assert company_for("stats.g.doubleclick.net") == "Google"
    assert company_for("v10.events.data.microsoft.com") == "Microsoft"
    assert company_for("cdn.segment.com") == "Twilio Segment"
    assert company_for("unknown.example") is None


@pytest.fixture(scope="module")
def pipeline():
    return Pipeline(interval=1.0)


def test_hostile_app_name_is_escaped_and_malware_fails(pipeline):
    evil = r"C:\Users\someone\AppData\Local\Temp\<script>alert(1)</script>.exe"
    pipeline.ranker.observe(Connection(
        id="1", pid=7, process_name="<script>alert(1)</script>.exe", process_exe=evil, laddr="", lport=1,
        raddr="50.16.16.211", rport=443, status="ESTABLISHED", scope="public", country="US",
        threat_indicator="50.16.16.211", threat="listed as QakBot botnet server by Feodo Tracker (abuse.ch)",
        flags=[Flag(id="known_malware", severity="critical", title="m")], first_seen=1, last_seen=2))
    pipeline.ranker.set_info(evil, ProcessInfo(pid=7, exe=evil, signature="unsigned"))
    data = collect(pipeline)
    page = render(data)
    assert data.grade == "F"
    assert "Needs attention" in page and "QakBot" in page
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert not re.search(r"<script|src=|href=|@import|url\(", page, re.I)  # self-contained, nothing loads
    assert "someone" not in page.lower()


def test_trackers_grouped_by_company():
    p = Pipeline(interval=1.0)
    app = r"C:\Program Files\App\app.exe"
    for i, host in enumerate(["www.google-analytics.com", "stats.g.doubleclick.net", "www.googletagmanager.com"]):
        feed(p, make_conn(i, app, f"93.184.{i}.10", host))
    data = collect(p)
    google = next(x for x in data.companies if x["company"] == "Google")
    assert {"google-analytics.com", "g.doubleclick.net", "googletagmanager.com"} <= set(google["domains"])
    assert r"C:\Program Files" not in render(data)


def test_report_period():
    assert report_since() is None
    p = Pipeline(interval=1.0)
    app = r"C:\Program Files\App\app.exe"
    old = make_conn(1, app, "93.184.1.10", "www.google-analytics.com")
    feed(p, old)
    p.ranker.apps[app].endpoints[(old.raddr, old.rport)].last_seen = time.time() - 3600
    set_report_since(time.time() - 60)
    assert abs(report_since() - (time.time() - 60)) < 5
    assert collect(p, since=report_since()).apps_watched == 0
    feed(p, make_conn(2, app, "93.184.2.10", "stats.g.doubleclick.net"))
    assert collect(p, since=report_since()).trackers == 1
