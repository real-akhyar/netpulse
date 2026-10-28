"""FastAPI app: dashboard + REST + live WebSocket feed (SPEC §4). The Pipeline does the work;
this module only serves its state and fans its events out to browsers."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from netpulse.action.apply import BlockStore
from netpulse.action.block import generate, plan, safe_hostname
from netpulse.alerts import Alerter
from netpulse.llm.client import Explainer, LLMConfig
from netpulse.models import Connection
from netpulse.pipeline import Pipeline
from netpulse.report import collect, render, report_since, set_report_since
from netpulse.store import HistoryStore
from netpulse.trust import TrustStore

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent / "web"
COALESCE_SECONDS = 0.3
IDLE_TICK_SECONDS = 1.0  # re-check aggregates/stats at least this often, even with no events
FALLBACK_ORIGIN_AFTER = 8.0  # seconds of traffic before guessing origin from remote countries
DEFAULT_ORIGIN = {"lat": 20.0, "lon": 0.0, "label": "You"}
RECENT_CLOSED_MAX = 400
RECENT_CLOSED_SECONDS = 600.0


def _visible(conn: Connection) -> bool:
    return conn.scope != "loopback"


class BlockRequest(BaseModel):
    """Nothing selected = everything caught so far ("Export blocklist")."""

    domains: list[str] = Field(default_factory=list)
    pids: list[int] = Field(default_factory=list)
    apps: list[str] = Field(default_factory=list)  # Connection.app / ProcessAgg.app keys
    format: Literal["hosts", "windows_fw", "pf"] = "hosts"


class TrustRequest(BaseModel):
    kind: Literal["app", "domain"]
    value: str = Field(min_length=1, max_length=1024)
    name: Optional[str] = Field(None, max_length=200)  # display label (e.g. "chrome.exe")


class ApplyBlockRequest(BaseModel):
    """Nothing selected = every culprit (like "Export blocklist")."""

    apps: list[str] = Field(default_factory=list)


class UndoBlockRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)  # empty = undo everything
    all: bool = False


class ResetRequest(BaseModel):
    target: Literal["caught", "timeline", "report", "map", "trust"]


class AlertsRequest(BaseModel):
    level: Literal["all", "critical", "off"]


class ExplainRequest(BaseModel):
    domains: list[str] = Field(default_factory=list, max_length=30)


class Hub:
    def __init__(self, interval: float, llm: Optional[LLMConfig] = None, min_severity: str = "low",
                 history: Optional[HistoryStore] = None, trust: Optional[TrustStore] = None,
                 alerter: Optional[Alerter] = None, blocks: Optional[BlockStore] = None):
        self.min_severity = min_severity
        self.history = history
        self.trust = trust or TrustStore()
        self.alerter = alerter
        self.blocks = blocks or BlockStore()
        self.block_lock = asyncio.Lock()  # one apply/undo (and one admin prompt) at a time
        self.events: asyncio.Queue = asyncio.Queue()
        self.pipeline = Pipeline(interval=interval, out=self.events, history=history, trust=self.trust,
                                 alerter=alerter)
        self.explainer = Explainer(llm) if llm else None
        self.clients: set[WebSocket] = set()
        self.origin: dict = dict(DEFAULT_ORIGIN)
        self._sent_processes: dict[str, str] = {}
        self._sent_stats: Optional[str] = None
        self._tasks: list[asyncio.Task] = []
        # Recently closed connections, replayed to browsers that (re)connect so the detail view and
        # lingering arcs survive a page reload.
        self._live: dict[str, Connection] = {}
        self.recent_closed: OrderedDict[str, tuple[Connection, float]] = OrderedDict()

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> None:
        for coro in (self.pipeline.run(), self._broadcast_loop(), self._resolve_origin()):
            self._tasks.append(asyncio.create_task(coro))

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    # ---- state views -----------------------------------------------------

    @property
    def paused(self) -> bool:
        return self.pipeline.monitor.paused

    def set_paused(self, paused: bool) -> None:
        self.pipeline.monitor.paused = paused

    def connections(self) -> list[Connection]:
        return [c for c in self.pipeline.monitor.connections.values() if _visible(c)]

    def stats(self) -> dict:
        return {
            **self.pipeline.stats(),
            "paused": self.paused,
            "llm": self.explainer is not None,
            "min_severity": self.min_severity,
            "history": self.history is not None,
            "alerts": self.alerter.level if self.alerter else "off",
            "blocks": {"count": len(self.blocks.entries), "supported": self.blocks.applier.supported,
                       "apps": sorted({a for e in self.blocks.entries.values() for a in e.apps})},
            "trust": {"apps": sorted(self.trust.trust.apps), "domains": sorted(self.trust.trust.domains)},
            "restored": self.pipeline.restored,
            # Bonus signal: tracker domains looked up on this machine that no caught connection explains.
            "unattributed": self.pipeline.unattributed_tracker_lookups()[:12],
            "unattributed_malware": self.pipeline.unattributed_malware_lookups()[:8],
        }

    def snapshot(self) -> list[dict]:
        messages: list[dict] = [{"type": "origin", "origin": self.origin}]
        cutoff = time.time() - RECENT_CLOSED_SECONDS
        for conn, closed_at in self.recent_closed.values():
            if closed_at >= cutoff:
                messages.append({"type": "connection_new", "connection": conn.model_dump(mode="json")})
                messages.append({"type": "connection_closed", "id": conn.id, "closed_at": closed_at})
        messages += [{"type": "connection_new", "connection": c.model_dump(mode="json")} for c in self.connections()]
        messages += [{"type": "process_update", "process": p.model_dump(mode="json")} for p in self.pipeline.ranker.processes()]
        messages.append({"type": "stats", "stats": self.stats()})
        return messages

    # ---- origin ----------------------------------------------------------

    async def _resolve_origin(self) -> None:
        origin = await asyncio.to_thread(self.pipeline.geo.own_origin)
        if origin is None:
            await asyncio.sleep(FALLBACK_ORIGIN_AFTER)
            countries = [c.country for c in self.pipeline.monitor.connections.values() if c.scope == "public"]
            origin = self.pipeline.geo.fallback_origin(countries)
        self.origin = origin
        await self._send_all([{"type": "origin", "origin": origin}])

    # ---- broadcasting ----------------------------------------------------

    async def _broadcast_loop(self) -> None:
        while True:
            batch: list[dict] = []
            try:
                batch.append(await asyncio.wait_for(self.events.get(), IDLE_TICK_SECONDS))
                await asyncio.sleep(COALESCE_SECONDS)
                while not self.events.empty():
                    batch.append(self.events.get_nowait())
            except asyncio.TimeoutError:
                pass
            try:
                messages = self._coalesce(batch) + self._aggregate_changes()
                if messages:
                    await self._send_all(messages)
            except Exception:
                log.exception("broadcast failed; continuing")

    def _coalesce(self, batch: list[dict]) -> list[dict]:
        """One message per connection per window. Connection objects are enriched in place, so
        serializing at flush time already carries every update that arrived in the window."""
        messages: list[dict] = []
        seen: set[str] = set()
        for event in batch:
            if event["type"] == "connection_closed":
                closed = self._live.pop(event["id"], None)
                if closed is not None:
                    self.recent_closed[event["id"]] = (closed, time.time())
                    while len(self.recent_closed) > RECENT_CLOSED_MAX:
                        self.recent_closed.popitem(last=False)
                messages.append(event)
                continue
            conn: Connection = event["connection"]
            if not _visible(conn) or conn.id in seen:
                continue
            self._live[conn.id] = conn
            seen.add(conn.id)
            messages.append({"type": event["type"], "connection": conn.model_dump(mode="json")})
        return messages

    def _aggregate_changes(self) -> list[dict]:
        messages: list[dict] = []
        for proc in self.pipeline.ranker.processes():
            dumped = proc.model_dump(mode="json")
            encoded = json.dumps(dumped, sort_keys=True)
            if self._sent_processes.get(proc.app) != encoded:
                self._sent_processes[proc.app] = encoded
                messages.append({"type": "process_update", "process": dumped})
        stats = self.stats()
        encoded = json.dumps(stats, sort_keys=True)
        if encoded != self._sent_stats:
            self._sent_stats = encoded
            messages.append({"type": "stats", "stats": stats})
        return messages

    async def _send_all(self, messages: list[dict]) -> None:
        if not self.clients or not messages:
            return
        frames = [json.dumps(m) for m in messages]
        for ws in list(self.clients):
            try:
                for frame in frames:
                    await ws.send_text(frame)
            except Exception:
                self.clients.discard(ws)

    async def serve_client(self, ws: WebSocket) -> None:
        await ws.accept()
        try:
            for message in self.snapshot():
                await ws.send_text(json.dumps(message))
            self.clients.add(ws)
            while True:
                await ws.receive_text()  # we don't expect messages; this just detects disconnect
        except WebSocketDisconnect:
            pass
        finally:
            self.clients.discard(ws)


def create_app(
    interval: float = 2.0, llm: Optional[LLMConfig] = None, min_severity: str = "low",
    history: Optional[HistoryStore] = None, trust: Optional[TrustStore] = None,
    alerter: Optional[Alerter] = None, blocks: Optional[BlockStore] = None,
) -> FastAPI:
    hub = Hub(interval, llm, min_severity, history, trust, alerter, blocks)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        hub.start()
        yield
        await hub.stop()

    app = FastAPI(title="netpulse", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.hub = hub
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/connections")
    async def connections() -> list[dict]:
        return [c.model_dump(mode="json") for c in hub.connections()]

    @app.get("/api/processes")
    async def processes() -> list[dict]:
        return [p.model_dump(mode="json") for p in hub.pipeline.ranker.processes()]

    @app.get("/api/origin")
    async def origin() -> dict:
        return hub.origin

    @app.post("/api/pause")
    async def pause() -> dict:
        hub.set_paused(True)
        return {"paused": True}

    @app.post("/api/resume")
    async def resume() -> dict:
        hub.set_paused(False)
        return {"paused": False}

    @app.post("/api/block")
    async def block(req: BlockRequest) -> dict:
        ranker = hub.pipeline.ranker
        keys = list(req.apps) + [k for k in (ranker.app_for_pid(p) for p in req.pids) if k]
        if keys:
            targets = ranker.block_targets(keys)
        elif req.domains:
            targets = []
        else:
            targets = ranker.block_targets(min_severity=hub.min_severity)
        result = generate(targets, req.format, extra_domains=req.domains)
        return {"text": result.text, "filename": result.filename, "domains": result.domains, "ips": result.ips}

    @app.post("/api/reset")
    async def reset(req: ResetRequest) -> dict:
        """Per-area reset: caught | timeline | report (new report period) | map | trust."""
        if req.target in ("timeline",) and hub.history is None:
            raise HTTPException(409, "history is off (--no-history), so there's no timeline to clear")
        if req.target == "report":
            set_report_since(time.time())
        elif req.target == "map":
            hub.recent_closed.clear()
        else:
            await asyncio.to_thread(hub.pipeline.reset, req.target)
        if req.target == "caught":
            hub._sent_processes.clear()  # clients drop their list; fresh process updates follow
        await hub._send_all([{"type": "reset", "target": req.target}])
        return {"ok": True, "target": req.target}

    @app.get("/report", include_in_schema=False)
    async def privacy_report(download: bool = False) -> HTMLResponse:
        """Shareable privacy report card: self-contained HTML, app names only, paths redacted."""
        page = render(collect(hub.pipeline, hub.min_severity, since=report_since()))
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="netpulse-report-{time.strftime("%Y-%m-%d")}.html"'
        return HTMLResponse(page, headers=headers)

    @app.get("/api/blocks")
    async def blocks_status() -> dict:
        return await asyncio.to_thread(hub.blocks.summary)

    @app.post("/api/blocks/apply")
    async def blocks_apply(req: ApplyBlockRequest) -> dict:
        """One-click block: hosts entries for the app(s)' tracker/suspicious domains and firewall rules
        for their non-shared suspicious IPs. May wait for the Windows admin prompt."""
        ranker = hub.pipeline.ranker
        targets = ranker.block_targets(req.apps or None, min_severity=hub.min_severity)
        domains, ips = plan(targets)
        if not domains and not ips:
            return {"ok": False, "error": "nothing to block for that selection", "warnings": []}
        async with hub.block_lock:
            res = await asyncio.to_thread(hub.blocks.add, domains, ips)
        return {"ok": res.ok, "error": res.error, "warnings": res.warnings, "domains": len(domains), "ips": len(ips),
                **(await asyncio.to_thread(hub.blocks.summary))}

    @app.post("/api/blocks/undo")
    async def blocks_undo(req: UndoBlockRequest) -> dict:
        if not req.all and not req.ids:
            raise HTTPException(400, "say which blocks to undo, or all")
        async with hub.block_lock:
            res = await asyncio.to_thread(hub.blocks.remove, None if req.all else req.ids)
        return {"ok": res.ok, "error": res.error, "warnings": res.warnings,
                **(await asyncio.to_thread(hub.blocks.summary))}

    @app.post("/api/alerts")
    async def set_alerts(req: AlertsRequest) -> dict:
        """Desktop alert level for this run: all | critical | off."""
        if hub.alerter is None:
            raise HTTPException(409, "desktop alerts were disabled at startup")
        hub.alerter.level = req.level
        return {"alerts": req.level}

    @app.get("/api/trust")
    async def trust_rules() -> dict:
        return {"rules": hub.trust.rules()}

    @app.post("/api/trust")
    async def trust_add(req: TrustRequest) -> dict:
        """Mark an app or domain as expected. Domains must be valid hostnames; apps must be ones
        netpulse has seen (their key is the exe path or process name)."""
        if req.kind == "domain":
            value = safe_hostname(req.value)
            if value is None:
                raise HTTPException(400, "not a valid domain name")
        else:
            value = req.value
            if value not in hub.pipeline.ranker.apps or any(ord(ch) < 32 for ch in value):
                raise HTTPException(400, "unknown app")
        name = "".join(ch for ch in (req.name or value) if ord(ch) >= 32)[:200]
        hub.trust.add(req.kind, value, name)
        hub.pipeline.reapply_trust()
        return {"ok": True, "rules": hub.trust.rules()}

    @app.post("/api/untrust")
    async def trust_remove(req: TrustRequest) -> dict:
        if not hub.trust.remove(req.kind, req.value):
            raise HTTPException(404, "no such trust rule")
        hub.pipeline.reapply_trust()
        return {"ok": True, "rules": hub.trust.rules()}

    @app.get("/api/timeline")
    async def timeline(since: Optional[float] = None, app_key: Optional[str] = Query(None, alias="app"),
                       all: bool = False, limit: int = Query(300, le=2000)) -> dict:
        """What each app did and when — first occurrence of every finding, newest first.
        Default hides info-level events (like "X went online for the first time")."""
        if hub.history is None:
            return {"enabled": False, "events": []}
        levels = None if all else {"low", "medium", "high", "critical"}
        events = await asyncio.to_thread(hub.history.timeline, since, app_key, limit, levels)
        return {"enabled": True, "events": events}

    @app.get("/api/history")
    async def app_history(app_key: str = Query(..., alias="app")) -> dict:
        """One app's saved endpoints and findings — fills the detail view after a restart."""
        if hub.history is None:
            return {"enabled": False, "endpoints": [], "findings": []}
        endpoints = await asyncio.to_thread(hub.history.endpoints, app_key)
        findings = await asyncio.to_thread(hub.history.timeline, None, app_key, 200, None)
        for row in endpoints:
            row.pop("flags", None)
        return {"enabled": True, "endpoints": endpoints[:300], "findings": findings}

    @app.post("/api/explain")
    async def explain(req: ExplainRequest) -> dict:
        if hub.explainer is None:
            raise HTTPException(404, "LLM explainer is off (start with --llm and set NETPULSE_LLM_* env vars)")
        domains = [d for d in (safe_hostname(x) for x in req.domains) if d]
        return {"explanations": await hub.explainer.explain(domains)}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await hub.serve_client(ws)

    return app
