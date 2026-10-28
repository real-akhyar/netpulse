"""Block-rule exports and the one-click block plan."""

import pytest

from netpulse.action.block import generate, plan
from netpulse.detect.rank import BlockTarget

TARGETS = [
    BlockTarget(
        "python.exe", r"C:\Python314\python.exe",
        {"www.google-analytics.com", "google-analytics.com", "stats.g.doubleclick.net", "g.doubleclick.net"},
        {"172.66.147.243": "example.com"},
    ),
    BlockTarget(
        "cmd.exe", r"C:\Windows\System32\cmd.exe", set(),
        {"31.7.60.154": "www.google.com.backendmain.cyou", "203.0.113.9": None},
    ),
    # Hostile values, as if planted via DNS / process names:
    BlockTarget(
        "evil'app.exe\r\nRemove-Item C:\\", r"C:\Apps\it's.exe",
        {"x.com'; Remove-Item C:\\ -Recurse #", "ok-tracker.net\n0.0.0.0 bank.com", "UPPER.Tracker.NET.", "-leading.dash.com"},
        {"192.168.1.5": None, "8.8.8.8; calc": None, "1.2.3.4": "fine.example.net"},
    ),
    BlockTarget("bad-exe.exe", "C:\\Apps\\bad\nNew-Item.exe", set(), {"5.6.7.8": None}),
]


@pytest.mark.parametrize("fmt", ["hosts", "windows_fw", "pf"])
def test_exports_are_ascii_and_reject_hostile_values(fmt):
    text = generate(TARGETS, fmt, extra_domains=["ads.example.org", "bad domain"]).text
    assert text.isascii()
    for bad in ("Remove-Item C:", "bank.com", "calc", "192.168.1.5", "New-Item", "-leading"):
        assert bad not in text, f"hostile value leaked: {bad!r}"


def test_hosts_export_lists_trackers_and_normalises():
    r = generate(TARGETS, "hosts", extra_domains=["ads.example.org"])
    assert "0.0.0.0 www.google-analytics.com" in r.text
    assert "0.0.0.0 upper.tracker.net" in r.text
    assert "0.0.0.0 ads.example.org" in r.text
    assert r.domains == r.text.count("0.0.0.0 ")


def test_firewall_export_blocks_raw_ips_and_has_undo():
    text = generate(TARGETS, "windows_fw").text
    assert "-RemoteAddress 31.7.60.154" in text
    assert "Remove-NetFirewallRule -Group 'netpulse'" in text


def test_unknown_format_rejected():
    with pytest.raises(ValueError):
        generate(TARGETS, "iptables")


def test_plan_normal_app_blocks_only_trackers():
    # A legit app reconnecting on a timer (update check, sync) must not lose its server.
    t = BlockTarget("python.exe", None, {"google-analytics.com"}, {"140.82.112.3": "github.com"},
                    kinds={"140.82.112.3": "beaconing"})
    domains, ips = plan([t])
    assert set(domains) == {"google-analytics.com"}
    assert ips == {}


def test_plan_critical_app_blocks_its_beacons():
    t = BlockTarget("svchost.exe", None, set(), {"31.7.60.154": "c2.example.net"},
                    kinds={"31.7.60.154": "beaconing"}, critical=True)
    domains, ips = plan([t])
    assert set(domains) == {"c2.example.net"}
    assert set(ips) == {"31.7.60.154"}


def test_plan_known_malware_always_blocked():
    t = BlockTarget("app.exe", None, set(), {"31.7.60.154": "bad.example.net"},
                    kinds={"31.7.60.154": "known_malware"})
    domains, ips = plan([t])
    assert set(domains) == {"bad.example.net"}
    assert set(ips) == {"31.7.60.154"}
