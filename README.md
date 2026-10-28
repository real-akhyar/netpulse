# netpulse

**See what your apps are really doing behind your back — and block it.**

A live world map of every connection your computer makes, with the trackers named, the culprit
apps called out in plain English, and one click to shut them up. Runs offline. No account, no API
key, no admin needed to watch.

![netpulse demo: tracker arcs firing across the globe as apps phone home, then a culprit gets blocked](docs/demo.gif)

> 🎬 *Demo GIF goes here — record it with the steps in [docs/DEMO.md](docs/DEMO.md).*

## Quick start

```bash
pip install -e .
netpulse watch
```

Your browser opens on the dashboard. Use your laptop normally for 30 seconds and watch it fill up.
(Python 3.11+. Prefer the terminal? `netpulse watch --headless`.)

## What it catches

netpulse ties every connection to **the app that made it**, then tells you what it found:

> 🔴 **chrome.exe** is contacting 9 ad/tracking servers across 5 countries.
> `google-analytics.com` `doubleclick.net` `scorecardresearch.com`

> 🔴 **OfficeC2RClient.exe** is contacting 1 ad/tracking server across 1 country.
> `events.data.microsoft.com`

> 🟠 **cmd.exe** is quietly beaconing to `www.google.com.backendmain.cyou` every ~6s.

That last one is real: while netpulse was being built, it caught a hijacked `cmd.exe` on the
developer's own laptop calling home to a fake-Google domain every few seconds. A command prompt has
no business on the network at all.

It finds:

- **Known malware** — connections to ~214,000 listed malware, phishing and botnet domains and
  ~33,000 threat IPs (offline snapshots of HaGeZi Threat Intelligence, URLhaus and Feodo Tracker).
  It also raises the alarm when something merely *looks up* a known-malware domain.
- **Trackers** — connections to ~59,000 known ad, analytics and telemetry domains.
- **Beacons** — apps reconnecting to the same server on a regular timer (jitter-tolerant).
- **Bare IPs** — apps repeatedly talking to addresses with no hostname at all.
- **Suspicious processes** — judged by *who* the app is, not just where it connects:
  - built-in Windows tools that should never be online (`cmd.exe`, `rundll32`, `mshta`, `wscript`…)
    suddenly connecting out, or PowerShell/`certutil` calling out — escalated if Word or Excel
    started them;
  - fake system files: a `svchost.exe` or `lsass.exe` running from outside the Windows folder;
  - programs running from Temp, Downloads, the Recycle Bin or the Public folder;
  - binaries whose digital signature is broken (tampered after signing).
- **Where it all goes** — country and network owner for every endpoint, drawn on the globe.

Click any culprit to see every host it talked to and why it was flagged, plus who the app really
is: its **verified publisher** (code signature — or a warning if it's unsigned or tampered), what
started it, when, and with which command line (obvious secrets like `--token=…` are redacted).

## Runs offline, needs no key, watches only your machine

- **Offline:** the tracker list and IP-location data ship inside the package. Nothing is downloaded
  at runtime. The only network lookups are reverse DNS, plus one optional public-IP check to place
  you on the globe. Without internet, it still works and shows IPs.
- **No key, no account:** the core features don't use an AI or any cloud service.
- **Only this computer:** netpulse reads your operating system's own connection table — the same
  information `netstat` shows. No packet capture, no network sniffing, nothing about other devices.
  It's a personal privacy tool in the spirit of Little Snitch and GlassWire.
- **No admin needed:** run it as a normal user and you'll see your own apps. Run the terminal as
  administrator to also see protected system processes.

## Blocking what it finds

Hit **Block** on a culprit (or **Export blocklist** for everything caught), then **🚫 Block now**.
On Windows, netpulse applies the block for you after one admin prompt, and lists it under
**Blocked** with an **Undo** button (or **Undo all**):

- It only ever edits **its own marked section** of the hosts file
  (`# >>> netpulse blocks` … `# <<< netpulse blocks <<<`) and its own firewall rules (group
  `netpulse`). Your own hosts lines are left exactly as they were, and a one-time backup
  (`hosts.netpulse.bak`) is made before the first change. Undo all puts the file back as it was.
- The admin-level helper is passed inline (nothing on disk to tamper with), checks a SHA-256 of
  its request before reading it, and re-validates every hosts line and IP itself.
- After each change netpulse reads the hosts file back to confirm. Windows Defender sometimes
  reverts hosts entries that block **Microsoft's own** domains — netpulse warns you when that
  might happen, and a reverted entry shows as struck-through in the Blocked list.

Prefer to do it yourself, or not on Windows? The same modal gives you the rules to copy or save:

- **Hosts file** — `0.0.0.0 tracker.example.com` lines for every tracker hostname the app
  contacted. Paste them at the end of `C:\Windows\System32\drivers\etc\hosts` (open Notepad *as
  administrator*), save, then run `ipconfig /flushdns`. On macOS/Linux it's `/etc/hosts`.
- **Windows Firewall** — `New-NetFirewallRule` commands for suspicious raw IPs (beacons, bare
  IPs). Paste them into an administrator PowerShell. Every rule goes into a `netpulse` group, so
  `Remove-NetFirewallRule -Group 'netpulse'` undoes all of them.
- **macOS pf** — a pf table for the same raw IPs.

Tracker *domains* go in the hosts file, not the firewall: their IPs are shared Google/CDN servers,
and blocking those would break unrelated sites. For the same reason, a suspicious or malware IP that
sits on a shared cloud/CDN network (Cloudflare, Google, Amazon…) is left out of firewall rules with
a note — its hostname is still blocked in the hosts file. Both one-click blocking and the exports
follow these rules.

## Getting named trackers from your browser

netpulse learns which hostname an app looked up by reading the **Windows DNS cache**. Most
desktop apps use it automatically. Chrome and Edge, by default, resolve names themselves and skip
it — so in those browsers you'll see IPs and server names instead of tracker names. To get named
trackers from your browser, either:

- use **Firefox** with DNS-over-HTTPS off, or
- turn off Chrome/Edge's built-in DNS client, Secure DNS and QUIC with three policy values.

[docs/DEMO.md](docs/DEMO.md) has the exact commands, how to undo them, and a 2-minute pre-flight
check.

## History: what happened while you were away

netpulse remembers. Findings are saved to a small local database, so culprits are still there after
a restart, and the dashboard's **Timeline** tab shows the first time each app did each thing —
"python.exe contacted google-analytics.com", "svchost.exe started running from Temp" — grouped by
day, with a badge for anything new since your last visit. From the terminal:

```bash
netpulse history            # last 7 days; --days 30, --all for info-level events
```

The history stays on your machine (`%LOCALAPPDATA%\netpulse\history.db` on Windows), keeps 30 days,
and is wiped with `netpulse history --clear`. Run `netpulse watch --no-history` to keep nothing.

## Privacy report card

Click **📄 Report** in the dashboard (or run `netpulse report`) for a one-page report card you can
share: a **grade from A to F** for your computer, the nosiest apps with their verdicts, **trackers
by company** (Google, Meta, Microsoft, Comscore…), where your data goes by country, and anything
that needs attention.

It's built to be shared safely: app names only — no file paths, usernames, machine name or your own
IP address (profile paths inside verdicts are redacted to `C:\Users\…`) — and it's a single
self-contained HTML file with no scripts or external resources, so it opens anywhere and phones
nowhere.

```bash
netpulse report             # from the last 30 days of history -> netpulse-report-YYYY-MM-DD.html
netpulse report --open      # and open it
```

Grading: known malware is always an F, an app behaving like malware caps the grade at D, and
trackers, beacons and bare-IP connections lower it gradually. Trusted apps aren't counted.

## Desktop alerts

You don't have to watch the dashboard. netpulse pops a native notification when something new
happens — an app phones home for the first time, a new tracker shows up, an app starts beaconing —
and immediately for anything critical (known malware, a fake system file, `cmd.exe` going online).
Click it to open the dashboard.

It's built not to nag: each finding alerts once ever (even across restarts), news is batched per app
with at most one summary a minute, apps already running when netpulse starts don't announce
themselves, and trusted apps and domains stay quiet (known malware never does).

```bash
netpulse watch --alerts critical   # or: all (default), off
netpulse test-alert                # check notifications show up on this machine
```

The 🔔 button in the dashboard switches between all / critical / off while it runs. On Windows,
notifications appear as "Windows PowerShell" (netpulse uses PowerShell to show them, so there's
nothing extra to install); Focus Assist can hide them.

## Trust: mute what you expect

Not every finding is a problem for you. Hit **Trust** on a culprit (or **trust** next to any flagged
connection in its detail view) and netpulse stops calling it out:

- **Trust an app** — it leaves the Caught list, the timeline and "export everything", and its
  traffic is drawn as normal.
- **Trust a domain** (and its subdomains) — a tracker you're fine with, or a false positive, stops
  counting for every app.

One thing trust never hides: if a trusted app contacts a **known-malware** server, it's called out
anyway — apps get compromised. Everything you trust is listed under "Trusted by you" with an
Untrust button, and untrusting brings the findings straight back.

```bash
netpulse trust                     # list rules (--remove VALUE, --clear)
```

Rules live in `trust.json` next to the history file and work with `--no-history` too. (Edits made
with `netpulse trust` apply to a running dashboard after it restarts; the dashboard's own buttons
apply instantly.)

## Optional: plain-English tracker explanations

With an LLM key you can add a one-sentence "what is this tracker?" explanation to each culprit.
It's **off by default** and only sends tracker domain names — never anything about your machine.

```powershell
$env:ANTHROPIC_API_KEY = "..."   # or OPENAI_API_KEY / NETPULSE_LLM_API_KEY
netpulse watch --llm
```

Options: `NETPULSE_LLM_PROVIDER` (`anthropic` | `openai` | `none`), `NETPULSE_LLM_MODEL`, and
`NETPULSE_LLM_BASE_URL` for OpenAI-compatible or Azure endpoints. If the call fails, the normal
verdicts stay exactly as they are.

## Command line

```
netpulse watch [--headless] [--port 8900] [--host 127.0.0.1] [--interval 2]
               [--min-severity low] [--llm] [--no-history] [--alerts all|critical|off]
netpulse history [--days 7] [--all] [--clear]
netpulse trust [--remove VALUE] [--clear]
netpulse test-alert
netpulse report [-o FILE] [--open]
```

- `--headless` — live terminal table and Caught summary, no browser.
- `--min-severity` — only call out apps whose worst finding is at least this severe
  (`info` / `low` / `medium` / `high` / `critical`).
- `?map=2d` on the dashboard URL forces the flat map, which is also used automatically when WebGL
  isn't available.

**Windows notes:** run from native Windows, not WSL (WSL can't see Windows' connections). If
Windows Firewall asks about Python the first time, "Private networks" is enough; the dashboard
only listens on `127.0.0.1`.

## Data sources

All bundled in [`netpulse/data/`](netpulse/data/SOURCES.md) and [`netpulse/web/vendor/`](netpulse/data/SOURCES.md).

| What | Source | Snapshot | License |
|---|---|---|---|
| IP → country | [DB-IP IP to Country Lite](https://db-ip.com) | 2026-10 | CC BY 4.0 — *IP Geolocation by DB-IP* |
| IP → network owner | [DB-IP IP to ASN Lite](https://db-ip.com) | 2026-10 | CC BY 4.0 — *IP Geolocation by DB-IP* |
| Tracker domains | [OISD small](https://oisd.nl) (59,447 domains) | 2026-10-28 | GPL-3.0, redistributed unmodified |
| Tracker supplement | netpulse's curated list of major analytics/ad/telemetry domains | 2026-10-28 | MIT |
| Tracker → company map | netpulse's curated map of ~75 tracker domains to their companies | 2026-10-28 | MIT |
| Malware domains & IPs | [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists) (mini) | 2026-10-27 | GPL-3.0, redistributed as data |
| Malware hosts | [URLhaus](https://urlhaus.abuse.ch) via [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) | 2026-10-28 | CC0 |
| Botnet C2 IPs | [Feodo Tracker](https://feodotracker.abuse.ch) (abuse.ch) | 2026-10-28 | CC0 |
| Country centroids | [Google DSPL countries.csv](https://developers.google.com/public-data/docs/canonical/countries_csv) | 2026-10-28 | CC BY 4.0 |
| World outlines | [Natural Earth](https://www.naturalearthdata.com/) 1:110m | 2026-10-28 | Public domain |
| Globe renderer | [globe.gl](https://github.com/vasturiano/globe.gl) 2.46.2 (includes three.js) | — | MIT |

## Roadmap

- **One-click blocking on macOS & Linux** — today it's Windows-only; the exports work everywhere.
- **Per-app bandwidth** — how much data each app is sending, not just where.
- **QUIC / HTTP3 visibility** — Windows doesn't report remote addresses for UDP, so QUIC traffic is
  currently invisible.
- **Optional SNI capture** — opt-in packet inspection to name HTTPS endpoints in browsers that
  bypass the DNS cache.
- **macOS & Linux DNS-cache readers** — today they fall back to reverse DNS.
- **Mobile** — the same idea for phones.

## Ethics

netpulse shows what **your own computer** sends, so you can see it and control it. It doesn't
inspect other devices, capture other people's traffic, or attack anything. Use it on machines
you own.

## License

MIT — see [LICENSE](LICENSE). Bundled data keeps its own license (see [Data sources](#data-sources)).
