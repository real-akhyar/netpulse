"""Privacy report card: a one-page, shareable HTML summary — a grade for this machine, the nosiest
apps, trackers by company, where data goes, and anything critical.

Made to be shared, so it's privacy-safe by construction: app *names* only (no exe paths, command
lines, IPs, usernames or machine name), Windows profile paths inside verdicts redacted, and one
self-contained file — no scripts, no external fonts or images, nothing that phones home when opened.
"""

from __future__ import annotations

import dataclasses
import html
import json
import platform
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from netpulse import __version__
from netpulse.detect.companies import company_for
from netpulse.detect.rank import Ranker

# C:\Users\<name>\... -> C:\Users\…\...  (the username is the identifying part)
_USER_PATH = re.compile(r"(?i)\b([a-z]:\\users\\)[^\\\s,;:)]+")
GRADE_BANDS = [(10, "A"), (25, "B"), (45, "C"), (70, "D")]  # penalty below N -> grade
GRADE_WORDS = {"A": "Quiet", "B": "Mostly quiet", "C": "Chatty", "D": "Leaky", "F": "Needs attention"}
GRADE_COLORS = {"A": "#8fae7e", "B": "#a9b06a", "C": "#e3b341", "D": "#d07a3a", "F": "#e5484d"}


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


def _settings_path():
    from netpulse.store import default_path

    return default_path().with_name("settings.json")


def report_since() -> Optional[float]:
    """Start of the current report period (set by "New report period"), or None for everything."""
    try:
        return float(json.loads(_settings_path().read_text(encoding="utf-8")).get("report_since") or 0) or None
    except (OSError, ValueError, TypeError):
        return None


def set_report_since(ts: Optional[float]) -> None:
    path = _settings_path()
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        settings = {}
    settings["report_since"] = ts
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def _period_ranker(ranker: Ranker, since: float) -> Ranker:
    """A view of the ranker holding only activity since `since` (same trust)."""
    view = Ranker(ranker.trust)
    for key, app in ranker.apps.items():
        endpoints = {k: e for k, e in app.endpoints.items() if e.last_seen >= since}
        if endpoints:
            view.apps[key] = dataclasses.replace(app, endpoints=endpoints, first_seen=max(app.first_seen, since))
    return view


def collect(pipeline, min_severity: str = "low", since: Optional[float] = None) -> ReportData:
    """Everything the report needs, from a pipeline (live, or restored from history), counting only
    activity since the start of the report period when one is set."""
    ranker = _period_ranker(pipeline.ranker, since) if since else pipeline.ranker
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
        f'<div class="bar-track"><i style="width:{max(2, round(100 * n / top))}%;background:{color}"></i></div>'
        f'<div class="bar-n">{n}</div></div>'
        for label, n, note in rows
    )


def render(data: ReportData) -> str:
    color = GRADE_COLORS[data.grade]
    period = (f"{_date(data.period_start)} to {_date(data.period_end)}" if data.period_start else _date(data.generated))
    readouts = [("Apps watched", data.apps_watched, ""), ("Apps flagged", len(data.culprits), ""),
                ("Tracker domains", data.trackers, "red" if data.trackers else ""),
                ("Companies", len([c for c in data.companies if c["company"] != "Other / unknown"]), ""),
                ("Countries", len(data.countries), ""), ("Malware", len(data.malware), "malware" if data.malware else "")]
    sev_color = {"critical": "#e5484d", "high": "#e5484d", "medium": "#e3b341", "low": "#8a7a3a"}

    alarms = ""
    if data.malware or data.critical:
        items = "".join(f"<li><b>Known malware:</b> {_e(m)}</li>" for m in data.malware)
        items += "".join(f"<li><b>{_e(c['name'])}:</b> {_e(c['verdict'])}</li>" for c in data.critical)
        alarms = (f'<section class="alarm"><h2>Needs attention</h2><ul>{items}</ul>'
                  '<p class="muted">Run a full antivirus scan (Windows Security, Scan options, Microsoft Defender '
                  "Offline scan) and block what you don't recognise.</p></section>")

    culprit_rows = "".join(
        f'<tr><td><b>{_e(c["name"])}</b><span class="score">{c["nosiness"]}</span><div class="meter"><i style="width:{max(3, c["nosiness"])}%;'
        f'background:{sev_color.get(c["severity"], "#7d8590")}"></i></div></td>'
        f'<td>{_e(c["verdict"])}<div class="chips">{"".join(f"<span>{_e(t)}</span>" for t in c["trackers"])}</div></td></tr>'
        for c in data.culprits[:10]
    ) or '<tr><td colspan="2" class="muted">No app was flagged.</td></tr>'

    companies = _bars([(c["company"], len(c["domains"]), ", ".join(c["apps"][:3])) for c in data.companies[:10]], "#e5484d")
    countries = _bars([(name, n, "") for name, n in data.countries], "#7d8590")
    trusted = (f'<p class="muted">{data.trusted_apps} app{"s" if data.trusted_apps != 1 else ""} you marked as trusted '
               f'{"are" if data.trusted_apps != 1 else "is"} not shown (known malware would be).</p>') if data.trusted_apps else ""
    readout_html = "".join(f'<div class="{cls}"><dt>{_e(label)}</dt><dd>{n}</dd></div>' for label, n, cls in readouts)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>netpulse privacy report: grade {data.grade}</title>
<style>
:root {{ --bg:#141414; --line:#262626; --line2:#363636; --text:#e6e3dc; --muted:#9a968e; --faint:#65625d;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,ui-monospace,monospace; color-scheme:dark; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
  -webkit-font-smoothing:antialiased; }}
main {{ max-width:860px; margin:0 auto; padding:28px 16px 40px; }}
header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:16px; flex-wrap:wrap;
  padding-bottom:14px; border-bottom:1px solid var(--line2); }}
.brand {{ font-weight:700; font-size:14px; }} .brand span {{ font-weight:400; color:var(--faint); }}
h1 {{ margin:6px 0 2px; font-size:22px; letter-spacing:-.3px; }}
h2 {{ margin:0 0 10px; font-size:10.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--faint); font-weight:600; }}
.muted {{ color:var(--muted); font-size:12.5px; }} .mono {{ font-family:var(--mono); }}
.hero {{ display:grid; grid-template-columns:auto 1fr; gap:24px; align-items:center; padding:22px 0; border-bottom:1px solid var(--line); }}
.grade {{ font:700 96px/1 var(--mono); color:{color}; padding:0 8px 0 16px; border-left:3px solid {color}; }}
.word {{ font-size:18px; font-weight:600; color:{color}; }}
.summary {{ margin:4px 0 6px; font-size:15px; }}
.readouts {{ display:grid; grid-template-columns:repeat(6,1fr); margin:0 0 22px; border-bottom:1px solid var(--line); }}
.readouts div {{ padding:12px 12px 12px 0; border-right:1px solid var(--line); margin-right:12px; }}
.readouts div:last-child {{ border-right:0; margin-right:0; }}
.readouts dt {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.08em; color:var(--faint); }}
.readouts dd {{ margin:2px 0 0; font:600 20px var(--mono); }}
.readouts .red dd {{ color:#e5484d; }}
.readouts .malware {{ background:#e5484d; padding-left:10px; }} .readouts .malware dt, .readouts .malware dd {{ color:#fff; }}
section {{ margin-bottom:26px; }}
.alarm {{ border-left:3px solid #e5484d; background:rgba(229,72,77,.12); padding:12px 16px; }} .alarm h2 {{ color:#e5484d; }}
.alarm ul {{ margin:0 0 8px; padding-left:18px; }}
table {{ width:100%; border-collapse:collapse; border-top:1px solid var(--line); }}
td {{ padding:10px 10px 10px 0; border-bottom:1px solid var(--line); vertical-align:top; font-size:13.5px; overflow-wrap:anywhere; }}
td:first-child {{ width:30%; }}
.score {{ float:right; font:12px var(--mono); color:var(--muted); }}
.meter {{ height:2px; background:var(--line); margin-top:7px; }} .meter i {{ display:block; height:100%; }}
.chips {{ margin-top:6px; display:flex; flex-wrap:wrap; gap:4px; }}
.chips span {{ font:11px var(--mono); color:#e5484d; border:1px solid rgba(229,72,77,.35); border-radius:2px; padding:0 5px;
  max-width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:28px; }}
.bar {{ display:grid; grid-template-columns:1fr 34px; gap:3px 10px; padding:6px 0; border-bottom:1px solid var(--line); }}
.bar-label {{ grid-column:1 / -1; display:flex; justify-content:space-between; gap:8px; font-size:13px; }}
.bar-label b {{ font-weight:600; }}
.bar-label span {{ color:var(--faint); font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.bar-track {{ height:2px; background:var(--line); margin-top:7px; }} .bar-track i {{ display:block; height:100%; }}
.bar-n {{ font:12px var(--mono); color:var(--muted); text-align:right; }}
footer {{ margin-top:28px; padding-top:12px; border-top:1px solid var(--line); font-size:12px; color:var(--faint); }}
@media (max-width:700px) {{ .hero {{ grid-template-columns:1fr; }} .readouts {{ grid-template-columns:repeat(3,1fr); }}
  .readouts div {{ border-bottom:1px solid var(--line); }} .grid2 {{ grid-template-columns:1fr; }} td:first-child {{ width:38%; }} }}
@media print {{ :root {{ --bg:#fff; --text:#111; --line:#ddd; --line2:#bbb; --muted:#555; --faint:#777; color-scheme:light; }} }}
</style></head>
<body><main>
<header>
  <div><div class="brand">netpulse <span>privacy report</span></div><h1>How nosy are the apps on this computer?</h1>
  <div class="muted">{_e(data.os_name)} · watched {_e(period)}</div></div>
  <div class="muted mono" style="text-align:right">generated {_e(_date(data.generated))}<br>netpulse {_e(__version__)}</div>
</header>
<div class="hero"><div class="grade">{_e(data.grade)}</div>
  <div><div class="word">{_e(GRADE_WORDS[data.grade])}</div><p class="summary">{_e(data.summary)}</p>
  <div class="muted">Graded from what netpulse saw: known malware, apps behaving like malware, trackers, beacons and
  bare-IP connections. Score {data.penalty}, lower is better.</div></div></div>
<dl class="readouts">{readout_html}</dl>
{alarms}
<section><h2>Nosiest apps</h2><table>{culprit_rows}</table>{trusted}</section>
<div class="grid2">
  <section><h2>Trackers by company</h2>{companies or '<p class="muted">No trackers seen.</p>'}</section>
  <section><h2>Where your data goes</h2>{countries or '<p class="muted">No internet connections recorded.</p>'}</section>
</div>
<footer>Made offline by netpulse on this computer. App names only: no file paths, usernames, machine name or
your own IP address. Save this page (Ctrl+S) to share it.</footer>
</main></body></html>
"""
