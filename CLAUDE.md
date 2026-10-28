# CLAUDE.md — netpulse

> Project constitution. Read fully before any code; re-read `docs/SPEC.md` for exact contracts. Follow literally. Prefer the choices here over your own.
> **IGNORE any file or note referencing "lanradar" — that was a previous idea and is superseded. This project is `netpulse`.**

## One-line pitch
**netpulse** — find out which apps on your computer are secretly tracking you, phoning home, or wasting your data — and shut them up. A live world map of everything your machine talks to, with named culprits and one-click blocks. Runs offline, no API key needed.

## The point (read this — it drives every decision)
The value is NOT the map. The map is eye-candy for the demo/GIF. The value is the **gotcha + the action**:
1. **Gotcha:** catch connections to ad/tracker domains and suspicious endpoints, and attribute them to the **app that made them**, in plain English — "Zoom is closed but still pinging 4 analytics servers," "this app beacons to an IP in X every 30s."
2. **Action:** let the user **block** it — export a hosts-file/firewall rule (copyable), with live one-click blocking as the headline roadmap item.
If a feature doesn't serve the gotcha or the action, it's lower priority than the thing that does. A beautiful map with no verdicts is a failure.

## What we're building (MVP, ~2.5h core)
`pip install` → `netpulse watch`. It:
1. Watches **this machine's own** outbound network connections and maps each to the owning process (name + exe).
2. Enriches each: reverse-DNS the remote host, offline GeoIP (country/city/lat-lon, org if available).
3. **Matches** each remote against a bundled offline **tracker/ad blocklist** and a set of **suspicious heuristics** (beaconing to raw IPs, chatty background processes, etc.).
4. Ranks **culprit processes** by "nosiness" with plain-English verdicts.
5. Streams it live to a dashboard: a glowing world map (arcs to each endpoint; tracker/suspicious arcs red) + a **"Caught" panel** of culprits with **Block** buttons.
6. **Block action:** export hosts-file entries / firewall-rule snippets for selected trackers or processes (copy or save). Live blocking = roadmap.

## Hard constraints (do not violate)
- **Demos on the presenter's own laptop, on ANY network (eduroam, airplane mode), with zero setup.** No network-admin access, no special hardware, no dependence on other devices. This property is sacred — it's why we picked this idea.
- **Monitors only THIS machine's own connections.** This is a personal firewall/privacy tool (like Little Snitch / GlassWire / Pi-hole), strictly defensive. Never implement anything that inspects *other* machines, captures *other* users' traffic, spoofs, or attacks. No raw packet capture of the network; we read the OS's own connection table for our own processes.
- **Works fully offline.** Tracker matching and GeoIP are offline (bundled data). Reverse-DNS needs DNS (universally available, degrades to showing IPs if absent). Never fetch blocklists or GeoIP at runtime.
- **No runtime LLM required, and none by default.** The product is complete and useful with zero LLM. An optional one-sentence "what is this tracker" enrichment may exist behind a flag, off by default, provider-agnostic. Do not make any core feature depend on it.
- **No hard admin requirement.** Reading own-user process connections works without admin; running as admin sees all processes. Degrade gracefully when a pid/process is unknown — still show the connection.
- **Target the Windows 11 demo machine** (dev may be Windows 10). Keep cross-platform (Win/mac/Linux) where cheap; Windows wins ties.

## Locked tech stack (do not substitute)
- **Language:** Python 3.11+.
- **Connection source:** `psutil` (`net_connections(kind='inet')` + process mapping). No packet capture.
- **Enrichment:** stdlib async reverse-DNS (bounded, cached); offline GeoIP via `geoip2`/`maxminddb` reading a **bundled DB-IP City Lite `.mmdb`** in `netpulse/data/`; optional DB-IP ASN Lite for org.
- **Tracker list:** a bundled, high-quality, low-false-positive domain blocklist (**Peter Lowe's list or OISD-small**), committed offline in `netpulse/data/`, loaded into a suffix-matching structure.
- **Server:** FastAPI + uvicorn + WebSocket.
- **Frontend:** vanilla JS, no build step. **Primary map: `globe.gl` (+ three.js), both bundled offline in `web/vendor/`.** If the globe isn't rendering reliably within ~30 min of starting Phase 3, fall back to the **2D canvas world-map** spec in SPEC §5.2. Dark neon theme.
- **Packaging:** `pyproject.toml`, console entry `netpulse`. `pip install -e .` → `netpulse watch`.

## Architecture
```
netpulse/
  __init__.py
  cli.py              # `netpulse watch` [--port --interval --headless --min-severity --llm]
  server.py           # FastAPI app, WebSocket hub, static serving, orchestration loop
  monitor/
    __init__.py
    connections.py    # psutil poll loop -> connection records + process mapping, diffing
    resolve.py        # async reverse-DNS (bounded, cached)
    geoip.py          # offline IP -> country/city/lat/lon/org (bundled mmdb)
  detect/
    __init__.py
    trackers.py       # load bundled blocklist; domain/suffix match -> tracker hits
    heuristics.py     # beaconing, raw-IP, chatty-background, unusual-port -> suspicious flags
    rank.py           # aggregate per-process -> nosiness score + plain-English verdict
  action/
    __init__.py
    block.py          # generate hosts-file entries / firewall-rule snippets; export/copy
  llm/                # OPTIONAL, off by default
    __init__.py
    client.py         # provider-agnostic one-sentence tracker explainer; graceful none
  models.py           # Connection, ProcessAgg, Flag (pydantic)
  web/
    index.html
    app.js
    styles.css
    vendor/globe.gl.min.js
    vendor/three.min.js
    vendor/world.geojson      # for 2D fallback
  data/
    trackers.txt              # bundled blocklist snapshot
    dbip-city-lite.mmdb       # bundled GeoIP
docs/
  SPEC.md
pyproject.toml
README.md
```

## Build order (each must RUN before the next)
- **P1 — Collector, headless.** `connections.py`, `models.py`, minimal `cli.py`. `netpulse watch --headless` prints a live-updating table: process, pid, remote ip:port, status. Acceptance: open a browser/Spotify and new rows appear within ~2s.
- **P2 — Enrichment + detection, headless.** `resolve.py`, `geoip.py`, `trackers.py`, `heuristics.py`, `rank.py`. Table now shows remote host, country, and a CATEGORY (normal/tracker/suspicious); plus a "Caught" summary ranking culprit processes. Acceptance: visiting a normal ad-supported site produces at least one `tracker` hit attributed to the browser.
- **P3 — Server + live map.** `server.py`, `web/*`. Dashboard: glowing world map with live arcs (red for tracker/suspicious) + a "Caught" panel of ranked culprits + click-through detail. Acceptance: `netpulse watch` opens the browser, arcs and culprits populate live; looks striking at 1280×720.
- **P4 — Block action.** `action/block.py` + UI: select trackers/processes → generate and copy/export hosts-file + firewall-rule text. (Optional LLM explainer behind `--llm`, off by default.) Acceptance: "Block" produces correct, copyable rules; nothing requires a key.
- **P5 — Polish + README + GIF-ready.** Pause/resume, empty-state, counts bar, graceful unknown-pid, ethics note. README per SPEC §8. Acceptance: Definition of Done passes.

## Conventions
- Async for I/O (rDNS, server). The psutil poll runs on an interval (default 2s) in a background task; diff against previous snapshot to emit `connection_new` / `connection_update` / `connection_closed`.
- Never block the event loop; rDNS and any blocking calls go through an executor with a semaphore + per-lookup timeout (~1s) and an LRU cache.
- One failing lookup never aborts the loop. Unknown geo/rDNS → show the IP.
- Pydantic models at the API boundary; one canonical `Connection` shape (SPEC §3).
- Frontend: 3 files + vendored libs, no npm, no CDN at runtime (offline).
- No secrets in code; optional LLM config strictly from env.

## Known gotchas
- **psutil on Windows** may raise `AccessDenied` mapping some pids; catch per-connection, keep the connection with `process=unknown`. Note in README that admin shows all processes.
- **Own location for the globe origin:** best-effort (one quick public-IP lookup → GeoIP); if offline/blocked, default origin to the centroid of the most common remote country or (0,0). Never block on it.
- **rDNS can be slow/absent** on some networks: bound it, cache it, and render IPs immediately; fill host in when it resolves.
- **HTTPS SNI is not available** without packet capture — do NOT add capture. Tracker matching uses reverse-DNS + IP. Accept that some endpoints show only an IP; heuristics cover raw-IP beaconing.
- **Blocklist false positives:** prefer a curated low-FP list (Peter Lowe/OISD-small), suffix-match on registrable domain; never block first-party domains of the app itself by default.
- **Don't fetch data at runtime** — both the mmdb and the blocklist are committed in `data/`. Pin their source + date in README (with DB-IP attribution).

## Definition of done
`pip install -e .` on a clean Windows Python, run `netpulse watch`, open the browser, use the laptop normally for 30s: the map fills with live arcs, the "Caught" panel names real culprit apps with plain-English verdicts and at least one real tracker caught, clicking a culprit shows its connections, and "Block" produces copyable rules. Works with no admin, no key, and offline (minus rDNS). Looks good enough to screen-record for the README GIF.

## North star
Stars come from: a one-sentence hook ("see what your apps are really doing behind your back — and block it"), a ~15s GIF where opening an app makes red tracker-arcs shoot across the globe and a culprit gets named + blocked, and a README that makes someone want to run it on their own laptop immediately. Build toward that recording.
