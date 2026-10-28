# docs/SPEC.md — netpulse technical specification

Read with `CLAUDE.md`. Exact contracts: monitoring, enrichment, detection, ranking, the data model, API/WebSocket, dashboard, block action, optional LLM. Implement to these. **Ignore anything referencing "lanradar" — superseded.**

---

## 1. Monitoring (`monitor/`)

### 1.1 connections.py
- Poll loop every `interval` seconds (default 2). Each tick:
  - `psutil.net_connections(kind='inet')` → list of (fd, family, type, laddr, raddr, status, pid).
  - Keep only connections with a **remote address** (`raddr`) that is **not** loopback/link-local/private-LAN-only when we care about "phoning home" — BUT keep LAN/private too, just categorize them `local`. We care most about public remotes. Classify remote as `public` / `private` / `loopback`.
  - Map `pid` → process `name` and `exe` via `psutil.Process(pid)`; on `AccessDenied`/`NoSuchProcess`, set `process_name="unknown"`, keep the connection.
  - Build a stable connection key: `(pid, raddr.ip, raddr.port, laddr.port)` — or `(process_name, raddr.ip, raddr.port)` if pid unstable.
- Diff against previous tick → emit events: `connection_new`, `connection_update` (status/last_seen/hit_count), `connection_closed`.
- Maintain per-connection `first_seen`, `last_seen`, `hit_count` (ticks seen), and a short timestamp history (for beacon detection).
- Runs as a background asyncio task; pushes events to an async queue the server drains.

### 1.2 resolve.py
- Async reverse-DNS for public remote IPs, via executor + semaphore (e.g. 64) + ~1s timeout, LRU-cached (e.g. 4096). Returns hostname or None.
- Also derive the **registrable domain** (eTLD+1) from the hostname for tracker matching (bundle a minimal public-suffix handling or a small PSL; a simple "last two labels, with a known-multi-part-TLD table" is acceptable for MVP).

### 1.3 geoip.py
- Load bundled `data/dbip-city-lite.mmdb` with `geoip2.database.Reader` (or `maxminddb`). For an IP return `{country, city, lat, lon}`; org/ASN via an optional ASN mmdb if bundled, else None. Cache results. Missing → None (render IP only).
- Provide `own_origin()`: best-effort public IP (one short STUN or HTTPS call with a tight timeout); map via GeoIP → origin lat/lon for globe arcs. On failure return a default and don't block.

---

## 2. Detection (`detect/`)

### 2.1 trackers.py
- Load `data/trackers.txt` (bundled snapshot of Peter Lowe's or OISD-small domain list; one domain per line, comments `#`). Store as a set + suffix-match: a remote domain matches if it equals, or is a subdomain of, any blocked domain.
- `match(host_or_domain) -> {matched: bool, rule: domain}`. Match on the resolved hostname and its registrable domain.

### 2.2 heuristics.py
Flags that don't need any external data (so the tool bites even fully offline / on raw IPs):
| Heuristic | category | severity | flag id / title |
|---|---|---|---|
| remote is tracker domain (from trackers.py) | tracker | medium | `tracker_contact` — "Contacted ad/tracker domain {domain}" |
| repeated connections to same public raddr at a regular cadence (≥N hits, low interval variance) | suspicious | medium | `beaconing` — "Regular beaconing to {ip} ({country})" |
| public remote is a **raw IP with no reverse-DNS** and recurring | suspicious | low | `raw_ip` — "Talks to a bare IP with no hostname ({ip})" |
| process contacting ≥K distinct tracker domains | — (process-level) | high | `many_trackers` — "{proc} contacted {K} trackers" |
| unusual external port (not 80/443/53/123/common) to a public host | suspicious | low | `unusual_port` — "Non-standard port {port} to {host}" |
| connection by a process whose remote count spikes while… (OPTIONAL background check; skip if cross-platform window state is hard) | info | low | `background_chatter` |
Tune N (e.g. ≥4 hits, interval variance small) and K (e.g. ≥3). Keep thresholds in constants.

### 2.3 rank.py
- Aggregate connections by process → `ProcessAgg`:
  - `connection_count`, `distinct_remotes`, `distinct_countries`, `tracker_count`, `suspicious_count`.
  - `nosiness = min(100, tracker_count*10 + suspicious_count*8 + distinct_countries*2 + distinct_remotes*0.5)`.
  - `verdict_text` (rule-based, plain English), e.g.:
    - trackers>0: "{proc} is contacting {tracker_count} ad/tracking servers across {distinct_countries} countries."
    - suspicious beaconing: "{proc} is quietly beaconing to {ip} every ~{period}s."
    - else clean: "{proc} — nothing suspicious."
- Expose a ranked culprit list (highest nosiness first), excluding clean processes from the "Caught" panel (but available in full list).

---

## 3. Data model (`models.py`)
```json
Connection {
  "id": "stable-key",
  "pid": 1234, "process_name": "chrome.exe", "process_exe": "C:/.../chrome.exe",
  "laddr": "192.168.0.10", "lport": 55342,
  "raddr": "140.82.113.3", "rport": 443, "status": "ESTABLISHED",
  "scope": "public",                       // public|private|loopback
  "remote_host": "server-x.githubassets.com",
  "remote_domain": "githubassets.com",
  "org": "GitHub, Inc.",                    // optional
  "country": "US", "city": "San Francisco", "lat": 37.77, "lon": -122.41,
  "category": "tracker",                    // normal|tracker|suspicious|local
  "tracker_rule": "doubleclick.net",        // if tracker
  "flags": [ {"id":"tracker_contact","severity":"medium","title":"...","detail":"..."} ],
  "first_seen": 1730000000.0, "last_seen": 1730000006.0, "hit_count": 4
}
ProcessAgg {
  "pid": 1234, "name": "chrome.exe", "exe": "...",
  "connection_count": 22, "distinct_remotes": 14, "distinct_countries": 5,
  "tracker_count": 6, "suspicious_count": 1,
  "nosiness": 78, "verdict_text": "chrome.exe is contacting 6 ad/tracking servers...",
  "top_trackers": ["doubleclick.net","google-analytics.com"]
}
Flag { "id": "...", "severity": "critical|high|medium|low|info", "title": "...", "detail": "..." }
```
`category` colors: normal=teal, tracker=red, suspicious=amber, local=grey.

---

## 4. API / WebSocket (`server.py`)
- `GET /` → dashboard.
- `GET /api/connections` → current connections (array).
- `GET /api/processes` → current ProcessAgg list (ranked).
- `GET /api/origin` → `{lat, lon, label}` for globe origin.
- `POST /api/pause` / `POST /api/resume` → toggle the poll loop.
- `POST /api/block` → body `{domains?:[...], pids?:[...], format:"hosts"|"windows_fw"|"pf"}` → returns `{text: "...", filename: "..."}` (generated rule text; does NOT apply it in MVP).
- `POST /api/explain` (optional, only if `--llm`) → one-sentence tracker explanations.
- `WS /ws` → live events:
```json
{"type":"origin","origin":{...}}
{"type":"connection_new","connection":{...}}
{"type":"connection_update","connection":{...}}
{"type":"connection_closed","id":"..."}
{"type":"process_update","process":{...}}           // ranked aggregate changed
{"type":"stats","stats":{"apps":12,"trackers":37,"countries":9,"suspicious":3}}
```
Coalesce bursts (~300ms). Server holds in-memory registries for connections + process aggregates.

---

## 5. Dashboard (`web/`)
Dark neon. Three regions.

**Top bar:** `netpulse` wordmark; live stat pills (apps watched, trackers caught, countries, suspicious); Pause/Resume; "Export blocklist". Small authorization note: "Monitors only this computer. For networks/devices you own."

### 5.1 Primary: globe (globe.gl + three.js, bundled)
- A dark 3D globe. **Arcs** from the user's origin to each remote endpoint; color by category (red tracker, amber suspicious, teal normal). New/active arcs animate; tracker arcs pulse. Points at endpoints sized by hit_count.
- Hover an arc/point → tooltip (process, host, country, category).
- Keep it legible at 1280×720. This is the GIF hero.

### 5.2 Fallback (use only if globe fights back within ~30 min)
- 2D world map: render `vendor/world.geojson` to canvas/SVG; draw glowing great-circle-ish arcs from origin to endpoints with the same color coding. Simpler, very reliable, still looks great.

**Right/side — "Caught" panel (the value):** ranked culprit list. Each row: app name + icon glyph, nosiness meter, one-line verdict ("Zoom is contacting 4 trackers while idle"), a **Block** button. Clicking a row → detail: its connections (host, country, category chips), its trackers, and a per-app Block.

**Block flow:** clicking Block (or "Export blocklist") calls `/api/block`, shows the generated hosts/firewall text in a modal with a **Copy** button and a note: "Add these to your hosts file / firewall to block. (Live one-click blocking is on the roadmap.)" Default format = hosts file; offer Windows firewall format on Windows.

Behavior: connect `/ws` on load; render origin, then stream arcs + culprits live. No build step; plain `app.js`.

---

## 6. Block action (`action/block.py`)
- `hosts` format: for each domain → `0.0.0.0 {domain}` (+ a header comment). For a pid/process → the union of its public tracker/suspicious domains.
- `windows_fw` format: `New-NetFirewallRule -DisplayName "netpulse block {domain/ip}" -Direction Outbound -Action Block -RemoteAddress {ip}` (IP-based for raw-IP cases; domain cases use hosts).
- `pf`/`iptables` snippets optional for mac/Linux.
- MVP **generates text only** (copy/save). Live apply (write hosts / add firewall rule, needs admin) is the headline roadmap item — do NOT implement auto-apply in MVP unless P1–P5 are done with time to spare.

---

## 7. Optional LLM (`llm/`, off by default)
- Only active with `--llm` or env `LANPULSE_LLM_PROVIDER` set. Provider-agnostic: `anthropic` | `openai` (+ `LANPULSE_LLM_BASE_URL` for OpenAI-compatible/Azure, e.g. the user's GPT 6.1 / Astra endpoint) | auto-detect from `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` | else disabled.
- Single purpose: given a tracker domain/org, return a one-sentence "what this is / why it's tracking you." Batched, strict JSON, defensively parsed. On any failure → omit (the rule-based verdict already stands). Never required.

---

## 8. CLI + README
**CLI (`cli.py`):** `netpulse watch [--port 8900] [--interval 2] [--headless] [--min-severity low] [--llm] [--host 127.0.0.1]`.
- Default: start monitor + server, open browser.
- `--headless`: print a live table (rich) of connections + a periodic "Caught" summary; no server.
- First run prints the authorization note + where data is bundled.

**README (Phase 5), in order:** hook line; big demo GIF placeholder (`docs/demo.gif`); 3-line Quick Start (`pip install -e .` → `netpulse watch`); "What it catches" with 3 example verdicts; "Runs offline, no key, monitors only your machine"; how to export/apply a block; optional LLM note; data-source attribution (DB-IP + blocklist, with dates); roadmap (live one-click block, per-app bandwidth, SNI via optional capture, mobile). The GIF is the #1 asset — record red tracker-arcs firing when you open an app, then a culprit named + blocked.

---

## 9. Ethics guardrail (non-negotiable)
- Monitors only the local machine's own connections (OS connection table), strictly defensive — a personal firewall/privacy tool. No packet capture, no monitoring of other hosts/users, no spoofing, no attacks.
- Blocking = outbound blocks on the user's own machine to trackers.
- Authorization note at CLI start + dashboard footer. README frames it as "see and control what *your* computer sends."
