"""Privacy report card: a one-page, shareable HTML summary — a grade for this machine, the nosiest
apps, trackers by company, where data goes, and anything critical.

Made to be shared, so it's privacy-safe by construction: app *names* only (no exe paths, command
lines, IPs, usernames or machine name), Windows profile paths inside verdicts redacted, and one
self-contained file — no scripts, no external fonts or images, nothing that phones home when opened.
"""

from __future__ import annotations

import html
import platform
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from netpulse import __version__
from netpulse.detect.companies import company_for

# C:\Users\<name>\... -> C:\Users\…\...  (the username is the identifying part)
_USER_PATH = re.compile(r"(?i)\b([a-z]:\\users\\)[^\\\s,;:)]+")
GRADE_BANDS = [(10, "A"), (25, "B"), (45, "C"), (70, "D")]  # penalty below N -> grade
GRADE_WORDS = {"A": "Quiet", "B": "Mostly quiet", "C": "Chatty", "D": "Leaky", "F": "Needs attention"}
GRADE_COLORS = {"A": "#2de2e6", "B": "#7ee787", "C": "#ffb020", "D": "#ff7b39", "F": "#ff2bd6"}


def redact(text: str) -> str:
    return _USER_PATH.sub(lambda m: m.group(1) + "…", text or "")


@dataclass
class ReportData:
    generated: float
    period_start: Optional[float]
    period_end: Optional[float]
    os_name: str
    apps_watched: int
    trusted_apps: int
    culprits: list[dict] = field(default_factory=list)  # {name, nosiness, severity, verdict, trackers}
    companies: list[dict] = field(default_factory=list)  # {company, domains, apps}
    countries: list[tuple[str, int]] = field(default_factory=list)  # (country name, endpoints)
    malware: list[str] = field(default_factory=list)  # "indicator — description"
    critical: list[dict] = field(default_factory=list)  # {name, verdict}
    trackers: int = 0
    beacons: int = 0
    bare_ips: int = 0
    high_alert_apps: int = 0
    critical_alert_apps: int = 0
    penalty: int = 0
    grade: str = "A"
    summary: str = ""


def grade(data: ReportData) -> tuple[int, str]:
    """Penalty points -> letter. Known malware is always an F; a critical process alert caps at D."""
    penalty = (
        35 * len(data.malware) + 25 * data.critical_alert_apps + 12 * data.high_alert_apps
        + min(30, 2 * data.trackers) + 6 * data.beacons + min(10, 2 * data.bare_ips)
    )
    letter = next((g for limit, g in GRADE_BANDS if penalty < limit), "F")
    if data.malware:
        letter = "F"
    elif data.critical_alert_apps and letter in "ABC":
        letter = "D"
    return penalty, letter


def collect(pipeline, min_severity: str = "low") -> ReportData:
    """Everything the report needs, from a pipeline (live, or restored from history)."""
    ranker = pipeline.ranker
    names = {code: name for code, (_, _, name) in pipeline.geo.centroids.items()}
    procs = ranker.processes()
    firsts = [p.first_seen for p in procs if p.first_seen]
    data = ReportData(
        generated=time.time(), period_start=min(firsts) if firsts else None,
        period_end=max((p.last_seen for p in procs), default=None),
        os_name=f"{platform.system()} {platform.release()}".strip(),
        apps_watched=len(procs), trusted_apps=sum(1 for p in procs if p.trusted),
    )

    companies: dict[str, dict] = defaultdict(lambda: {"domains": set(), "apps": set()})
    countries: Counter = Counter()
    for p in procs:
        if p.trusted:
            continue
        facts = ranker.facts(p.app)
        for rule in facts.trackers:
            entry = companies[company_for(rule) or "Other / unknown"]
            entry["domains"].add(rule)
            entry["apps"].add(p.name)
        for ep in ranker.apps[p.app].endpoints.values():
            if ep.country:
                countries[names.get(ep.country, ep.country)] += 1
        data.beacons += 1 if facts.beacon else 0
        data.bare_ips += sum(1 for kind in facts.suspicious.values() if kind == "raw_ip")
    data.companies = sorted(
        ({"company": c, "domains": sorted(v["domains"]), "apps": sorted(v["apps"])} for c, v in companies.items()),
        key=lambda c: (-len(c["domains"]), c["company"] == "Other / unknown", c["company"]),
    )
    data.countries = countries.most_common(10)

    totals = ranker.totals()
    data.trackers = len(totals["trackers"])
    data.malware = sorted({m for p in procs for m in p.malware} | set(pipeline.unattributed_malware_lookups()))
    for p in ranker.culprits(min_severity):
        alerts = {f.severity for f in p.flags if f.id != "many_trackers"}
        data.critical_alert_apps += "critical" in alerts
        data.high_alert_apps += "high" in alerts and "critical" not in alerts
        row = {"name": p.name, "nosiness": round(p.nosiness), "severity": p.severity or "low",
               "verdict": redact(p.verdict_text), "trackers": p.top_trackers[:4]}
        data.culprits.append(row)
        if p.severity == "critical":
            data.critical.append({"name": p.name, "verdict": row["verdict"]})

    data.penalty, data.grade = grade(data)
    bits = []
    if data.malware:
        bits.append(f"{len(data.malware)} known-malware contact{'s' if len(data.malware) != 1 else ''}")
    if data.critical_alert_apps:
        bits.append(f"{data.critical_alert_apps} app{'s' if data.critical_alert_apps != 1 else ''} behaving like malware")
    if data.trackers:
        n_co = len([c for c in data.companies if c["company"] != "Other / unknown"])
        bits.append(f"{data.trackers} tracker domain{'s' if data.trackers != 1 else ''}"
                    + (f" from {n_co} compan{'ies' if n_co != 1 else 'y'}" if n_co else ""))
    if data.beacons:
        bits.append(f"{data.beacons} app{'s' if data.beacons != 1 else ''} beaconing home")
    data.summary = ("; ".join(bits) + ".") if bits else "No trackers, beacons or malware seen. Nicely quiet."
    return data


# ---- rendering -------------------------------------------------------------

def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _date(ts: Optional[float]) -> str:
    return time.strftime("%d %b %Y, %H:%M", time.localtime(ts)) if ts else "—"


def _bars(rows: list[tuple[str, int, str]], color: str) -> str:
    top = max((n for _, n, _ in rows), default=1) or 1
    return "".join(
        f'<div class="bar"><div class="bar-label"><b>{_e(label)}</b><span>{_e(note)}</span></div>'
        f'<div class="bar-track"><i style="width:{max(4, round(100 * n / top))}%;background:{color}"></i></div>'
        f'<div class="bar-n">{n}</div></div>'
        for label, n, note in rows
    )


def render(data: ReportData) -> str:
    color = GRADE_COLORS[data.grade]
    period = (f"{_date(data.period_start)} → {_date(data.period_end)}" if data.period_start else _date(data.generated))
    tiles = [("apps watched", data.apps_watched), ("apps flagged", len(data.culprits)), ("tracker domains", data.trackers),
             ("companies", len([c for c in data.companies if c["company"] != "Other / unknown"])),
             ("countries", len(data.countries)), ("malware", len(data.malware))]
    sev_color = {"critical": "#ff2bd6", "high": "#ff3b5c", "medium": "#ffb020", "low": "#e8d36a"}

    alarms = ""
    if data.malware or data.critical:
        items = "".join(f"<li><b>Known malware:</b> {_e(m)}</li>" for m in data.malware)
        items += "".join(f"<li><b>{_e(c['name'])}:</b> {_e(c['verdict'])}</li>" for c in data.critical)
        alarms = (f'<section class="alarm"><h2>⚠ Needs attention</h2><ul>{items}</ul>'
                  f'<p class="muted">Run a full antivirus scan (Windows Security → Scan options → Microsoft Defender '
                  f'Offline scan) and block what you don\'t recognise.</p></section>')

    culprit_rows = "".join(
        f'<tr><td><b>{_e(c["name"])}</b><div class="meter"><i style="width:{max(3, c["nosiness"])}%;'
        f'background:{sev_color.get(c["severity"], "#2de2e6")}"></i></div></td>'
        f'<td>{_e(c["verdict"])}<div class="chips">{"".join(f"<span>{_e(t)}</span>" for t in c["trackers"])}</div></td></tr>'
        for c in data.culprits[:10]
    ) or '<tr><td colspan="2" class="muted">No app was flagged. 🎉</td></tr>'

    companies = _bars([(c["company"], len(c["domains"]), ", ".join(c["apps"][:3])) for c in data.companies[:10]], "#ff3b5c")
    countries = _bars([(name, n, "") for name, n in data.countries], "#2de2e6")
    trusted = (f'<p class="muted">{data.trusted_apps} app{"s" if data.trusted_apps != 1 else ""} you marked as trusted '
               f'{"are" if data.trusted_apps != 1 else "is"} not shown (known malware would be).</p>') if data.trusted_apps else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>netpulse privacy report — grade {data.grade}</title>
<style>
:root {{ --bg:#05070f; --panel:#0c1224; --line:rgba(120,160,255,.16); --text:#e6ecff; --muted:#8691b3; color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:radial-gradient(ellipse at top,#0d1838,var(--bg) 60%); color:var(--text);
  font:15px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif; }}
main {{ max-width:880px; margin:0 auto; padding:32px 16px 48px; }}
header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; }}
.brand {{ font-size:14px; letter-spacing:.5px; color:var(--muted); }} .brand b {{ color:#2de2e6; }}
h1 {{ margin:4px 0 2px; font-size:26px; }} h2 {{ margin:0 0 12px; font-size:17px; }}
.muted {{ color:var(--muted); font-size:13px; }}
.hero {{ display:grid; grid-template-columns:150px 1fr; gap:24px; align-items:center; margin:24px 0; padding:22px;
  background:var(--panel); border:1px solid var(--line); border-radius:16px; }}
.grade {{ width:150px; height:150px; border-radius:24px; display:grid; place-items:center; font-size:92px; font-weight:800;
  color:{color}; border:2px solid {color}; box-shadow:0 0 40px {color}55, inset 0 0 30px {color}22; text-shadow:0 0 24px {color}; }}
.word {{ font-size:22px; font-weight:700; color:{color}; }}
.tiles {{ display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin-bottom:22px; }}
.tile {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:12px; text-align:center; }}
.tile b {{ display:block; font-size:24px; }} .tile span {{ font-size:12px; color:var(--muted); }}
section {{ background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:18px 20px; margin-bottom:18px; }}
.alarm {{ border-color:#ff2bd6; box-shadow:0 0 24px #ff2bd633; }} .alarm h2 {{ color:#ff7ae6; }} .alarm ul {{ margin:0 0 8px; padding-left:20px; }}
table {{ width:100%; border-collapse:collapse; }} td {{ padding:10px 8px; border-top:1px solid var(--line); vertical-align:top; font-size:14px; }}
td:first-child {{ width:30%; }}
.meter {{ height:4px; background:rgba(255,255,255,.08); border-radius:4px; margin-top:6px; overflow:hidden; }} .meter i {{ display:block; height:100%; }}
.chips {{ margin-top:6px; display:flex; flex-wrap:wrap; gap:4px; }}
.chips span {{ font:11px ui-monospace,Consolas,monospace; color:#ff8fa3; border:1px solid rgba(255,59,92,.4); border-radius:999px; padding:1px 7px;
  max-width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
td {{ overflow-wrap:anywhere; }}
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }} .grid2 section {{ margin:0; }}
.bar {{ display:grid; grid-template-columns:1fr 34px; gap:4px 10px; margin-bottom:10px; }}
.bar-label {{ grid-column:1 / -1; display:flex; justify-content:space-between; gap:8px; font-size:13px; }}
.bar-label span {{ color:var(--muted); font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.bar-track {{ height:8px; background:rgba(255,255,255,.07); border-radius:6px; overflow:hidden; }} .bar-track i {{ display:block; height:100%; border-radius:6px; }}
.bar-n {{ font-size:12px; color:var(--muted); text-align:right; margin-top:-3px; }}
footer {{ margin-top:26px; font-size:12px; color:var(--muted); text-align:center; }}
@media (max-width:700px) {{ .hero {{ grid-template-columns:1fr; justify-items:center; text-align:center; }}
  .tiles {{ grid-template-columns:repeat(3,1fr); }} .grid2 {{ grid-template-columns:1fr; }} td:first-child {{ width:38%; }} }}
@media print {{ body {{ background:#fff; color:#111; }} section,.hero,.tile {{ background:#fff; border-color:#ccc; box-shadow:none; }}
  .muted,.bar-label span,.bar-n,.tile span,.brand {{ color:#555; }} }}
</style></head>
<body><main>
<header>
  <div><div class="brand">net<b>pulse</b> · privacy report</div><h1>How nosy are the apps on this computer?</h1>
  <div class="muted">{_e(data.os_name)} · watched {_e(period)}</div></div>
  <div class="muted" style="text-align:right">Generated {_e(_date(data.generated))}<br>netpulse {_e(__version__)}</div>
</header>
<div class="hero"><div class="grade">{_e(data.grade)}</div>
  <div><div class="word">{_e(GRADE_WORDS[data.grade])}</div><p style="margin:6px 0 4px;font-size:16px">{_e(data.summary)}</p>
  <div class="muted">Grade from what netpulse saw: known malware, apps behaving like malware, trackers, beacons and
  bare-IP connections. Score {data.penalty} (lower is better).</div></div></div>
<div class="tiles">{"".join(f'<div class="tile"><b>{n}</b><span>{_e(label)}</span></div>' for label, n in tiles)}</div>
{alarms}
<section><h2>Nosiest apps</h2><table>{culprit_rows}</table>{trusted}</section>
<div class="grid2">
  <section><h2>Trackers by company</h2>{companies or '<p class="muted">No trackers seen.</p>'}</section>
  <section><h2>Where your data goes</h2>{countries or '<p class="muted">No internet connections recorded.</p>'}</section>
</div>
<footer>Made offline by netpulse on this computer. App names only — no file paths, usernames, machine name or
your own IP address. Save this page (Ctrl+S) to share it.</footer>
</main></body></html>
"""
