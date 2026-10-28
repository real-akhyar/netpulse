"""Culprit ranking: process alerts (fake system files, dual-use tools...) and verdicts."""

import pytest

from netpulse.detect.rank import Ranker
from netpulse.models import Connection, ProcessInfo

from conftest import TRACKER, make_conn

T = r"C:\Users\someone\AppData\Local\Temp"
PROCESS_ALERT_IDS = {"masquerading", "silent_tool_online", "dual_use_tool_online", "bad_signature"}

# name, exe, signature, signer, parent, public?, expected flag ids, culprit?
CASES = [
    ("cmd.exe", r"C:\Windows\System32\cmd.exe", "valid", "Microsoft Windows", None, True, {"silent_tool_online"}, True),
    ("svchost.exe", T + r"\x\svchost.exe", "valid", "Python Software Foundation", "explorer.exe", True,
     {"masquerading", "risky_location"}, True),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "valid", "Microsoft Windows",
     "WINWORD.EXE", True, {"dual_use_tool_online"}, True),
    ("pwsh.exe", r"C:\Program Files\PowerShell\7\pwsh.exe", "valid", "Microsoft Corporation", "explorer.exe", True,
     {"dual_use_tool_online"}, True),
    ("app.exe", r"C:\Program Files\App\app.exe", "invalid", "Python Software Foundation", "explorer.exe", True,
     {"bad_signature"}, True),
    ("setup.exe", r"C:\Users\someone\Downloads\setup.exe", "valid", "Vendor", "explorer.exe", True, {"risky_location"}, True),
    ("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "valid", "Google LLC", "explorer.exe", True,
     set(), False),
    ("Antigravity IDE.exe", r"C:\Users\someone\AppData\Local\Programs\Antigravity IDE\Antigravity IDE.exe", "unsigned",
     None, "explorer.exe", True, {"unsigned"}, False),
    ("cmd.exe", r"C:\Windows\System32\cmd.exe", "valid", "Microsoft Windows", "explorer.exe", False, set(), False),
    ("svchost.exe", r"C:\Windows\System32\svchost.exe", "valid", "Microsoft Windows", "services.exe", True, set(), False),
]


@pytest.mark.parametrize("name, exe, sig, signer, parent, public, expect, culprit", CASES,
                         ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_process_alerts(name, exe, sig, signer, parent, public, expect, culprit):
    r = Ranker()
    r.observe(Connection(
        id="c", pid=100, process_name=name, process_exe=exe, laddr="", lport=1,
        raddr="31.7.60.154" if public else "192.168.1.9", rport=82, status="ESTABLISHED",
        scope="public" if public else "private", country="CH" if public else None,
        remote_host="www.google.com.backendmain.cyou" if public else None, first_seen=0, last_seen=0))
    r.set_info(exe, ProcessInfo(pid=100, exe=exe, signature=sig, signer=signer, parent_name=parent, parent_pid=2))
    p = r.processes()[0]
    flags = {f.id for f in p.flags}
    assert flags == expect
    assert (p in r.culprits()) == culprit
    if public:
        alert = r.process_alert(exe)
        should = bool(PROCESS_ALERT_IDS & flags) or ("risky_location" in flags and p.severity in ("high", "critical"))
        assert (alert is not None) == should


def test_trackers_make_a_culprit_with_plain_english_verdict():
    r = Ranker()
    app = r"C:\Apps\spotify.exe"
    r.observe(make_conn(1, app, "1.1.1.1", "stats.g.doubleclick.net", "g.doubleclick.net", flags=[TRACKER]))
    r.observe(make_conn(2, app, "2.2.2.2", "www.google-analytics.com", "google-analytics.com", flags=[TRACKER]))
    (p,) = r.culprits()
    assert p.tracker_count == 2
    assert "spotify.exe" in p.verdict_text and "2 ad/tracking" in p.verdict_text


def test_block_targets_carry_reasons_and_severity():
    r = Ranker()
    app = r"C:\Apps\x.exe"
    r.observe(make_conn(1, app, "1.1.1.1", "www.google-analytics.com", "google-analytics.com", flags=[TRACKER]))
    (t,) = r.block_targets([app])
    assert "google-analytics.com" in t.tracker_domains or "www.google-analytics.com" in t.tracker_domains
    assert t.critical is False
