# netpulse

**See what your apps are really doing behind your back — and block it.**

A live world map of every connection your computer makes, with the trackers named, the culprit
apps called out in plain English, and copy-paste rules to shut them up. Runs offline. No account,
no API key, no admin.

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

- **Trackers** — connections to ~59,000 known ad, analytics and telemetry domains.
- **Beacons** — apps reconnecting to the same server on a regular timer (jitter-tolerant).
- **Bare IPs** — apps repeatedly talking to addresses with no hostname at all.
- **Where it all goes** — country and network owner for every endpoint, drawn on the globe.

Click any culprit to see every host it talked to, and why it was flagged.

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

Hit **Block** on a culprit (or **Export blocklist** for everything caught) and netpulse generates
rules you can copy or save:

- **Hosts file** — `0.0.0.0 tracker.example.com` lines for every tracker hostname the app
  contacted. Paste them at the end of `C:\Windows\System32\drivers\etc\hosts` (open Notepad *as
  administrator*), save, then run `ipconfig /flushdns`. On macOS/Linux it's `/etc/hosts`.
- **Windows Firewall** — `New-NetFirewallRule` commands for suspicious raw IPs (beacons, bare
  IPs). Paste them into an administrator PowerShell. Every rule goes into a `netpulse` group, so
  `Remove-NetFirewallRule -Group 'netpulse'` undoes all of them.
- **macOS pf** — a pf table for the same raw IPs.

Tracker *domains* go in the hosts file, not the firewall: their IPs are shared Google/CDN servers,
and blocking those would break unrelated sites. netpulse never applies anything itself — you
review the rules and apply them. (Live one-click blocking is on the roadmap.)

## Getting named trackers from your browser

netpulse learns which hostname an app looked up by reading the **Windows DNS cache**. Most
desktop apps use it automatically. Chrome and Edge, by default, resolve names themselves and skip
it — so in those browsers you'll see IPs and server names instead of tracker names. To get named
trackers from your browser, either:

- use **Firefox** with DNS-over-HTTPS off, or
- turn off Chrome/Edge's built-in DNS client, Secure DNS and QUIC with three policy values.

[docs/DEMO.md](docs/DEMO.md) has the exact commands, how to undo them, and a 2-minute pre-flight
check.

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
               [--min-severity low] [--llm]
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
| Country centroids | [Google DSPL countries.csv](https://developers.google.com/public-data/docs/canonical/countries_csv) | 2026-10-28 | CC BY 4.0 |
| World outlines | [Natural Earth](https://www.naturalearthdata.com/) 1:110m | 2026-10-28 | Public domain |
| Globe renderer | [globe.gl](https://github.com/vasturiano/globe.gl) 2.46.2 (includes three.js) | — | MIT |

## Roadmap

- **Live one-click blocking** — apply hosts/firewall rules from the dashboard (with undo).
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
