"""Desktop alerts: a native notification when something new happens — an app phones home for the
first time, a new tracker appears, an app starts beaconing — or anything critical fires.

Built to inform, not nag:
- each (app, kind, key) alerts once ever (seeded from history, so restarts don't repeat old news);
- critical alerts go out within a second; everything else is batched per app every few seconds
  ("chrome.exe contacted 6 new trackers: …"), at most a few notifications per batch;
- "went online for the first time" is held back for a warm-up period, so apps that were already
  running when netpulse started don't all announce themselves at once;
- trusted apps and domains stay quiet — except known malware, which trust never hides.

Notifications use the OS itself — Windows toasts via PowerShell/WinRT, `osascript` on macOS,
`notify-send` on Linux — so there's no extra dependency. Text is passed on stdin / as argv, never
spliced into a command line.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Optional
from xml.sax.saxutils import escape

from netpulse.models import SEVERITY_RANK
from netpulse.trust import Trust

log = logging.getLogger(__name__)

LEVELS = ("all", "critical", "off")
BATCH_SECONDS = 8.0
APP_COOLDOWN_SECONDS = 60.0  # after notifying about an app, hold its further news this long, then summarise
WARMUP_SECONDS = 120.0
MAX_PER_BATCH = 3
# What counts as "new and worth a ping" below critical.
NEWS_KINDS = {"first_online", "tracker_contact", "beaconing"}
WINDOWS_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_PS_TOAST = (
    "$ErrorActionPreference='Stop';"
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime] > $null;"
    "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType=WindowsRuntime] > $null;"
    "$d = [Console]::In.ReadToEnd() | ConvertFrom-Json;"
    "$x = New-Object Windows.Data.Xml.Dom.XmlDocument; $x.LoadXml($d.xml);"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($d.app).Show("
    "[Windows.UI.Notifications.ToastNotification]::new($x))"
)


@dataclass
class Alert:
    app: str
    name: str
    kind: str
    key: str
    severity: str
    title: str
    detail: str
    label: str = ""  # what to show for the key (e.g. a hostname for a beacon keyed by IP)


def send_notification(title: str, body: str, url: Optional[str] = None) -> bool:
    """Show one native notification. Blocking (call from a thread); never raises."""
    title, body = title[:120], body[:300]
    try:
        if sys.platform == "win32":
            launch = f' activationType="protocol" launch="{escape(url, {chr(34): "&quot;"})}"' if url else ""
            xml = (f"<toast{launch}><visual><binding template=\"ToastGeneric\">"
                   f"<text>{escape(title)}</text><text>{escape(body)}</text></binding></visual></toast>")
            run = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_TOAST],
                input=json.dumps({"xml": xml, "app": WINDOWS_APP_ID}), capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if run.returncode != 0:
                log.debug("toast failed: %s", run.stderr.strip()[:300])
            return run.returncode == 0
        if sys.platform == "darwin":
            script = ["-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                      "-e", "end run"]
            return subprocess.run(["osascript", *script, title, body], capture_output=True, timeout=20).returncode == 0
        return subprocess.run(["notify-send", "--app-name=netpulse", title, body],
                              capture_output=True, timeout=20).returncode == 0
    except Exception:
        log.debug("notification failed", exc_info=True)
        return False


class Alerter:
    def __init__(self, level: str = "all", trust: Optional[Trust] = None, url: Optional[str] = None,
                 sender: Optional[Callable[[str, str, Optional[str]], bool]] = None,
                 warmup: float = WARMUP_SECONDS, batch_seconds: float = BATCH_SECONDS,
                 cooldown: float = APP_COOLDOWN_SECONDS):
        self.level = level if level in LEVELS else "all"
        self.trust = trust or Trust()
        self.url = url
        self.sender = sender or send_notification
        self.warmup = warmup
        self.batch_seconds = batch_seconds
        self.cooldown = cooldown
        self._last_notified: dict[str, float] = {}  # app -> when we last showed news about it
        self.started = time.time()
        self.seen: set[tuple[str, str, str]] = set()
        self._critical: list[Alert] = []
        self._news: list[Alert] = []
        self.sent = 0

    def seed(self, keys: set[tuple[str, str, str]]) -> None:
        """Findings already known from earlier runs never alert again."""
        self.seen |= keys

    def submit(self, alert: Alert) -> None:
        if self.level == "off":
            return
        key = (alert.app, alert.kind, alert.key)
        if key in self.seen:
            return
        self.seen.add(key)  # even if filtered below: "new" means new, not "new since I unmuted"
        malware = alert.kind == "known_malware"
        if not malware and (alert.app in self.trust.apps or self.trust.covers(alert.key)):
            return
        critical = SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK["critical"]
        if critical:
            self._critical.append(alert)
            return
        if self.level == "critical":
            return
        if alert.kind == "first_online" and time.time() - self.started < self.warmup:
            return  # already running when netpulse started — not news
        if alert.kind in NEWS_KINDS or SEVERITY_RANK.get(alert.severity, 0) >= SEVERITY_RANK["high"]:
            self._news.append(alert)

    # ---- delivery ----------------------------------------------------------

    def _messages(self) -> list[tuple[str, str]]:
        """Pending alerts -> (title, body) notifications, critical first, capped per batch."""
        out: list[tuple[str, str]] = []
        crit, self._critical = self._critical, []
        for a in crit[:MAX_PER_BATCH]:
            out.append((f"netpulse ⚠ {a.title}", a.detail))
        if len(crit) > MAX_PER_BATCH:
            names = sorted({a.name for a in crit[MAX_PER_BATCH:]})
            out.append((f"netpulse ⚠ {len(crit) - MAX_PER_BATCH} more critical findings", ", ".join(names)))
        return out

    def _news_messages(self) -> list[tuple[str, str]]:
        """Batched news, one notification per app — but an app we notified about recently waits
        out its cooldown, so a site loading trackers for a minute yields a ping and a summary,
        not a ping every few seconds."""
        news, self._news = self._news, []
        now = time.time()
        by_app: dict[str, list[Alert]] = defaultdict(list)
        for a in news:
            if now - self._last_notified.get(a.app, 0.0) < self.cooldown:
                self._news.append(a)  # keep for the summary after the cooldown
            else:
                by_app[a.app].append(a)
        for app in list(by_app)[:MAX_PER_BATCH]:
            self._last_notified[app] = now
        out = []
        for app, alerts in list(by_app.items())[:MAX_PER_BATCH]:
            out.append((f"netpulse: {alerts[0].name}", _summarise(alerts)))
        if len(by_app) > MAX_PER_BATCH:
            rest = list(by_app.values())[MAX_PER_BATCH:]
            out.append((f"netpulse: new activity from {len(rest)} more apps",
                        ", ".join(sorted({a[0].name for a in rest}))[:300]))
        return out

    async def run(self) -> None:
        last_news = time.time()
        while True:
            await asyncio.sleep(1.0)
            try:
                messages = self._messages()
                if time.time() - last_news >= self.batch_seconds:
                    last_news = time.time()
                    messages += self._news_messages()
                for title, body in messages:
                    if await asyncio.to_thread(self.sender, title, body, self.url):
                        self.sent += 1
            except Exception:
                log.exception("alert delivery failed; continuing")


def _summarise(alerts: list[Alert]) -> str:
    """One app's batch as a sentence: "chrome.exe went online for the first time; contacted 3 new
    trackers: a, b, c." plus any other findings' own titles."""
    verbs = []
    if any(a.kind == "first_online" for a in alerts):
        verbs.append("went online for the first time")
    trackers = [a.key for a in alerts if a.kind == "tracker_contact"]
    if trackers:
        shown = ", ".join(trackers[:3]) + (f" +{len(trackers) - 3} more" if len(trackers) > 3 else "")
        verbs.append(f"contacted {len(trackers)} new tracker{'s' if len(trackers) != 1 else ''}: {shown}")
    verbs += [f"started beaconing to {a.label or a.key}" for a in alerts if a.kind == "beaconing"]
    titles = [a.title for a in alerts if a.kind not in NEWS_KINDS and a.title]
    text = f"{alerts[0].name} " + "; ".join(verbs) + "." if verbs else ""
    return " ".join([text] + [t if t.endswith(".") else t + "." for t in titles]).strip()
