# PROMPTS.md — how to drive Claude Code to build netpulse

Copy-paste prompts for **you** (Akhyar), in order. `CLAUDE.md`, `docs/SPEC.md` are in this folder — Claude Code reads them. Paste one, let it finish and RUN, confirm the acceptance check, then paste the next. **The old lanradar docs are superseded; `docs/DECISIONS.md` now just says so — ignore it.**

## Before you start
1. Open a terminal in `C:\Users\akhya\Desktop\Hactoberfest`, run Claude Code there.
2. Native Windows **Python 3.11+** (`python --version`).
3. No hotspot, no admin, no special network needed — netpulse watches *your own laptop*. (Running the terminal as Admin later lets it see all processes, but it works without.)
4. For a lively demo: just use your laptop normally (browser, Spotify, etc.) while it runs — that's what fills the map.

---

## Prompt 0 — Orient
```
Read CLAUDE.md and docs/SPEC.md in full. Ignore docs/DECISIONS.md (it's a superseded note). Then give me back in under 15 lines: (1) one paragraph restating what netpulse is and — importantly — what problem it solves for a normal user (the gotcha + the action, not the map), (2) the 5 phases as a checklist, (3) anything ambiguous or risky for a Windows demo, especially around psutil connection+process mapping, bundling the GeoIP mmdb and tracker list offline, and the globe.gl render. Do NOT write code yet. Do NOT change the spec. List open questions.
```
Answer its questions (I can help), then continue.

---

## Prompt 1 — Phase 1: collector, headless
```
Implement Phase 1 from CLAUDE.md: the connection collector, headless. Create the package skeleton per the CLAUDE.md layout, plus pyproject.toml with console entry `netpulse` and deps (fastapi, uvicorn, psutil, pydantic, geoip2, rich). Implement models.py (the Connection pydantic model from SPEC §3, partial fields OK for now) and monitor/connections.py (psutil poll loop per SPEC §1.1: map pid->process, handle AccessDenied gracefully, classify scope public/private/loopback, diff ticks for new/update/closed, track first_seen/last_seen/hit_count + timestamp history). Add a minimal cli.py supporting `netpulse watch --headless` that prints a live-updating rich table (process, pid, remote ip:port, scope, status). Then run `pip install -e .` and `netpulse watch --headless`, open a browser/Spotify, and show me new rows appearing. One failing lookup must never crash the loop.
```
**Acceptance:** rows appear within ~2s of opening an app; your own processes are named; unknown pids show `unknown` but still list.

---

## Prompt 2 — Phase 2: enrichment + detection, headless
```
Implement Phase 2 from CLAUDE.md. Add monitor/resolve.py (async bounded cached reverse-DNS + registrable-domain extraction), monitor/geoip.py (offline lookups via a bundled DB-IP City Lite mmdb in netpulse/data/ — download and COMMIT it; also implement own_origin() best-effort), detect/trackers.py (load a bundled low-false-positive tracker domain list — Peter Lowe's or OISD-small — COMMIT it in netpulse/data/; suffix match), detect/heuristics.py (the heuristic table in SPEC §2.2: tracker_contact, beaconing, raw_ip, many_trackers, unusual_port), and detect/rank.py (per-process aggregation + nosiness score + plain-English verdict per SPEC §2.3). Wire into the headless mode so the table shows remote_host, country, and category (normal/tracker/suspicious/local), plus a periodic "Caught" summary ranking culprit processes with their verdicts. Keep ALL data offline/bundled — no runtime downloads of geoip or blocklist. Run it, browse a normal ad-supported news site, and show me at least one tracker caught and attributed to the browser.
```
**Acceptance:** browsing a normal site yields ≥1 `tracker` hit attributed to your browser; the Caught summary names it in plain English; works with no internet except rDNS.

---

## Prompt 3 — Phase 3: server + live map
```
Implement Phase 3 from CLAUDE.md. Create server.py (FastAPI: GET /, /api/connections, /api/processes, /api/origin, POST /api/pause|/resume, WS /ws with the exact event shapes in SPEC §4; in-memory registries; coalesce ~300ms) and the web/ frontend (index.html, styles.css, app.js). Dashboard per SPEC §5: top bar with live stat pills + Pause/Resume + Export-blocklist + authorization note; PRIMARY a dark globe using bundled web/vendor/globe.gl.min.js + three.min.js (download and COMMIT both — must work offline) drawing arcs from origin to each endpoint colored by category (red tracker / amber suspicious / teal normal), pulsing tracker arcs; a right-side "Caught" panel listing ranked culprit processes with nosiness meter + one-line verdict + Block button; click a culprit -> detail with its connections and trackers. cli.py `netpulse watch` starts monitor+server and opens the browser. Stream everything live over the WS. If globe.gl isn't rendering reliably after ~30 min, switch to the 2D canvas world-map fallback in SPEC §5.2 (bundle vendor/world.geojson). Run it, tell me the URL.
```
**Acceptance:** `netpulse watch` opens the browser; arcs + culprits populate live as you use the laptop; red arcs for trackers; clicking a culprit shows detail. Clean at 1280×720.

---

## Prompt 4 — Phase 4: block action (+ optional LLM)
```
Implement Phase 4 from CLAUDE.md. Create action/block.py per SPEC §6: generate hosts-file entries (0.0.0.0 domain) and Windows firewall rule snippets (New-NetFirewallRule, IP-based for raw-IP cases) for selected domains or a selected process's tracker/suspicious domains. Wire POST /api/block and the UI: Block buttons + "Export blocklist" open a modal showing the generated text with a Copy button and the note that live one-click blocking is on the roadmap. Default format hosts; offer Windows firewall format. Do NOT auto-apply (no admin writes) in this phase. Also add the OPTIONAL llm/client.py (SPEC §7): off by default, only with --llm or an LLM env var; provider-agnostic one-sentence tracker explainer, batched, strict JSON, degrades to omission on any failure. Confirm the whole app still works with no key and no --llm. Test the block output is correct and copyable.
```
**Acceptance:** Block/Export produces correct, copyable hosts + firewall text; nothing requires a key; `--llm` is purely additive.

---

## Prompt 5 — Phase 5: polish + README + GIF-ready
```
Implement Phase 5 from CLAUDE.md. Add: rescan/refresh that updates existing culprits instead of duplicating; graceful empty-state ("use your laptop and connections will appear"); error toasts; the live stats bar; graceful unknown-pid handling; the authorization note at CLI start and dashboard footer. Write README.md per SPEC §8: hook line, prominent demo GIF placeholder (docs/demo.gif), 3-line Quick Start, "What it catches" with 3 example verdicts, the offline/no-key/own-machine note, how to export+apply a block, optional-LLM note, data-source attribution (DB-IP + the blocklist with dates), and a roadmap (live one-click block, per-app bandwidth, optional SNI capture, mobile). Then do a clean end-to-end check and give me a bullet list confirming each Definition-of-Done item in CLAUDE.md passes or flagging what doesn't.
```
**Acceptance:** Definition of Done passes. Record the GIF next.

---

## After the build — the part that earns stars (~45 min)
1. **Record the GIF.** Run `netpulse watch`, then open a browser and a couple of apps so red tracker-arcs shoot across the globe; click a culprit and hit Block so the rule modal shows. ~15s, 1280×720, Windows ScreenToGif/ShareX. Save as `docs/demo.gif` (top of README). **This is the single biggest driver of stars.**
2. **Name + hook.** Repo `netpulse`; description: "See what your apps are really doing behind your back — a live map of every connection your computer makes, with the trackers named and one-click blocks. Offline, no account." Topics: `privacy`, `security`, `firewall`, `network-monitor`, `trackers`, `python`, `devtools`.
3. **License + push.** MIT, clean history, GIF committed.
4. **Launch post.** Show HN / r/privacy / r/selfhosted: "I built an open-source tool that shows which apps are secretly phoning home — and lets you block them." Lead with the GIF.

## If Claude Code gets stuck
- No connections: confirm native Windows (not WSL2); use the laptop (open apps); try running the terminal as Admin to see all processes.
- Geo/blocklist "not found": ensure the mmdb + trackers list are actually committed in `netpulse/data/` and loaded by path, not fetched.
- Globe blank: check devtools console; confirm globe.gl + three.min.js are bundled locally; if flaky, take the 2D fallback (SPEC §5.2).
- Too many false-positive trackers: switch to the low-FP list and suffix-match on registrable domain only.
- Keep fixes scoped to the current phase; re-point it at the relevant SPEC section.
```
