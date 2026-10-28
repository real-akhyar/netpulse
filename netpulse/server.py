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

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from netpulse.action.block import generate, safe_hostname
from netpulse.llm.client import Explainer, LLMConfig
from netpulse.models import Connection
from netpulse.pipeline import Pipeline

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


class ExplainRequest(BaseModel):
    domains: list[str] = Field(default_factory=list, max_length=30)


class Hub:
    def __init__(self, interval: float, llm: Optional[LLMConfig] = None, min_severity: str = "low"):
        self.min_severity = min_severity
        self.events: asyncio.Queue = asyncio.Queue()
        self.pipeline = Pipeline(interval=interval, out=self.events)
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
            # Bonus signal: tracker domains looked up on this machine that no caught connection explains.
            "unattributed": self.pipeline.unattributed_tracker_lookups()[:12],
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


def create_app(interval: float = 2.0, llm: Optional[LLMConfig] = None, min_severity: str = "low") -> FastAPI:
    hub = Hub(interval, llm, min_severity)

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
