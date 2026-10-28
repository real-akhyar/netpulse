"""`netpulse watch` entry point (SPEC §8)."""

from __future__ import annotations

import argparse
import asyncio
import logging
import time
from typing import Optional

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from netpulse.models import Connection
from netpulse.pipeline import Pipeline
from netpulse.store import HistoryStore

AUTH_NOTE = "netpulse monitors only THIS computer's own connections. Use it on machines you own."
NEW_HIGHLIGHT_SECONDS = 4.0
CAUGHT_ROWS = 6

CATEGORY_STYLE = {"malware": "bold magenta", "tracker": "bold red", "suspicious": "dark_orange", "normal": "cyan", "local": "grey50"}


def _remote(conn: Connection) -> str:
    host = conn.remote_host or (f"[{conn.raddr}]" if ":" in conn.raddr else conn.raddr)
    return f"{host}:{conn.rport}"


def _connections_table(pipeline: Pipeline, max_rows: int) -> Table:
    monitor = pipeline.monitor
    now = time.time()
    visible = [c for c in monitor.connections.values() if c.scope != "loopback"]
    loopback = len(monitor.connections) - len(visible)
    # Already-closed sockets we never saw alive: owner is unknowable, so they only bury real rows.
    conns = [c for c in visible if not (c.pid is None and c.status == "TIME_WAIT")]
    remnants = len(visible) - len(conns)
    conns.sort(key=lambda c: (c.first_seen, c.app.lower()), reverse=True)
    stats = pipeline.stats()
    cache = "on" if pipeline.dns_cache.available else "off (rDNS only)"

    malware = f"[bold magenta]{stats['malware']} MALWARE[/] · " if stats["malware"] else ""
    table = Table(
        title="[bold magenta]netpulse[/] — live connections (newest first)",
        caption=(
            f"{malware}{stats['apps']} apps · [red]{stats['trackers']} trackers[/] · {stats['countries']} countries · "
            f"[dark_orange]{stats['suspicious']} suspicious[/] · {len(conns)} open "
            f"({loopback} loopback + {remnants} closed-socket remnants hidden) · DNS cache {cache} · "
            f"every {monitor.interval:g}s · Ctrl+C to quit"
        ),
        expand=True,
    )
    table.add_column("", width=3, no_wrap=True)
    table.add_column("Process", style="bold", no_wrap=True, max_width=24)
    table.add_column("PID", justify="right", no_wrap=True, min_width=5)
    table.add_column("Remote", no_wrap=True, max_width=44, overflow="ellipsis")
    table.add_column("Country", no_wrap=True)
    table.add_column("Category", no_wrap=True, max_width=36, overflow="ellipsis")
    table.add_column("Status", no_wrap=True)
    table.add_column("Hits", justify="right", no_wrap=True, min_width=4)

    for conn in conns[:max_rows]:
        is_new = now - conn.first_seen < NEW_HIGHLIGHT_SECONDS and monitor.ticks > 1
        name_style = "grey50 italic" if conn.process_name == "unknown" else ""
        category = conn.category
        if category == "malware" and conn.threat_indicator:
            category = f"MALWARE ({conn.threat_indicator})"
        elif category == "tracker" and conn.tracker_rule:
            category = f"tracker ({conn.tracker_rule})"
        table.add_row(
            Text("NEW", style="bold green") if is_new else Text(""),
            Text(conn.process_name, style=name_style),
            str(conn.pid) if conn.pid else "-",
            Text(_remote(conn), style={"tracker": "red", "malware": "bold magenta"}.get(conn.category, "")),
            conn.country or "-",
            Text(category, style=CATEGORY_STYLE[conn.category]),
            conn.status,
            str(conn.hit_count),
        )
    if len(conns) > max_rows:
        table.add_row("", Text(f"… {len(conns) - max_rows} more", style="grey50"), "", "", "", "", "", "")
    return table


def _caught_table(pipeline: Pipeline, min_severity: str) -> Table:
    culprits = pipeline.ranker.culprits(min_severity)
    table = Table(title="[bold red]Caught[/] — nosiest apps this session", expand=True, show_edge=False)
    table.add_column("Nosiness", no_wrap=True, width=16)
    table.add_column("App", style="bold", no_wrap=True, max_width=24)
    table.add_column("Verdict", ratio=1)
    if not culprits:
        table.add_row("", Text("nothing caught yet", style="grey50"), Text("use your laptop normally — browse, open apps", style="grey50"))
    for p in culprits[:CAUGHT_ROWS]:
        filled = round(p.nosiness / 10)
        bar = Text("█" * filled, style="red" if p.nosiness >= 50 else "dark_orange") + Text("░" * (10 - filled), style="grey30")
        verdict = Text(p.verdict_text)
        if p.top_trackers:
            verdict.append(f"  [{', '.join(p.top_trackers[:3])}]", style="grey62")
        table.add_row(bar + Text(f" {p.nosiness:>3.0f}"), p.name, verdict)
    for hit in pipeline.unattributed_malware_lookups()[:3]:
        table.add_row(Text("  ☠ MALWARE", style="bold magenta"), Text("DNS cache", style="magenta"),
                      Text(f"something on this machine looked up {hit}", style="bold magenta"))
    lookups = pipeline.unattributed_tracker_lookups()
    if lookups:
        shown = ", ".join(lookups[:6]) + (f" +{len(lookups) - 6} more" if len(lookups) > 6 else "")
        table.add_row("", Text("DNS cache", style="grey62"), Text(f"tracker lookups by an unidentified app: {shown}", style="grey62"))
    return table


async def _watch_headless(interval: float, min_severity: str, history: Optional[HistoryStore]) -> None:
    console = Console()
    pipeline = Pipeline(interval=interval, history=history)
    task = asyncio.create_task(pipeline.run())
    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while True:
                await asyncio.sleep(0.5)
                if task.done():
                    task.result()  # surface a crash instead of rendering a frozen table
                caught = _caught_table(pipeline, min_severity)
                shown = min(len(pipeline.ranker.culprits(min_severity)), CAUGHT_ROWS)
                max_rows = max(5, console.size.height - 16 - shown)
                live.update(Group(_connections_table(pipeline, max_rows), caught))
    finally:
        task.cancel()


async def _watch_dashboard(
    host: str, port: int, interval: float, console: Console, llm: bool, min_severity: str,
    history: Optional[HistoryStore],
) -> None:
    import socket
    import webbrowser

    import uvicorn

    from netpulse.llm.client import load_config
    from netpulse.server import create_app

    llm_config = load_config(llm)
    if llm_config:
        console.print(f"[grey50]Optional tracker explainer: on — {llm_config.describe()} (sends tracker domain names only)[/]")
    elif llm:
        console.print("[yellow]--llm given but no usable API key/provider found — explainer stays off.[/]")

    with socket.socket() as probe:  # fail clearly instead of a uvicorn traceback
        if probe.connect_ex((host, port)) == 0:
            console.print(f"[red]Port {port} is already in use.[/] Try: netpulse watch --port {port + 1}")
            return
    url = f"http://{host}:{port}"
    app = create_app(interval, llm=llm_config, min_severity=min_severity, history=history)
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))

    async def open_when_ready() -> None:
        while not server.started:
            await asyncio.sleep(0.1)
        console.print(f"[bold green]Dashboard:[/] {url}   [grey50](Ctrl+C to quit)[/]")
        webbrowser.open(url)

    opener = asyncio.create_task(open_when_ready())
    try:
        await server.serve()
    finally:
        opener.cancel()


SEVERITY_COLOR = {"critical": "bold magenta", "high": "bold red", "medium": "dark_orange", "low": "yellow", "info": "grey50"}


def _show_history(console: Console, store: HistoryStore, days: float, show_all: bool) -> None:
    """`netpulse history`: the timeline in the terminal — what each app did and when."""
    levels = None if show_all else {"low", "medium", "high", "critical"}
    events = store.timeline(since=time.time() - days * 86400, limit=500, min_severity=levels)
    table = Table(title=f"[bold magenta]netpulse[/] — timeline, last {days:g} day(s) (newest first)", expand=True)
    table.add_column("First seen", no_wrap=True)
    table.add_column("App", style="bold", no_wrap=True, max_width=24)
    table.add_column("Severity", no_wrap=True)
    table.add_column("What happened", ratio=1)
    table.add_column("Seen", justify="right", no_wrap=True)
    for e in events:
        table.add_row(
            time.strftime("%Y-%m-%d %H:%M", time.localtime(e["first_seen"])),
            e["name"] or "?",
            Text(e["severity"], style=SEVERITY_COLOR.get(e["severity"], "")),
            e["title"],
            f"×{e['hits']}",
        )
    if not events:
        table.add_row("", Text("nothing recorded yet", style="grey50"), "", "run `netpulse watch` for a while", "")
    console.print(table)
    console.print(f"[grey50]History file: {store.path}  (clear it with: netpulse history --clear)[/]")


def main(argv: list[str] | None = None) -> None:
    # Plain ASCII: argparse prints in the console's legacy code page on Windows.
    parser = argparse.ArgumentParser(prog="netpulse", description="See what your apps are really doing - and block it.")
    sub = parser.add_subparsers(dest="command", required=True)
    watch = sub.add_parser("watch", help="watch this machine's connections live")
    watch.add_argument("--port", type=int, default=8900)
    watch.add_argument("--host", default="127.0.0.1")
    watch.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds")
    watch.add_argument("--headless", action="store_true", help="live terminal table, no dashboard")
    watch.add_argument("--min-severity", default="low", choices=["critical", "high", "medium", "low", "info"])
    watch.add_argument("--llm", action="store_true", help="optional one-sentence tracker explainer (off by default)")
    watch.add_argument("--no-history", action="store_true", help="don't save findings between runs")
    hist = sub.add_parser("history", help="show what apps did over the last days (saved findings)")
    hist.add_argument("--days", type=float, default=7, help="how far back to show (default 7)")
    hist.add_argument("--all", action="store_true", help="include info-level events like 'went online for the first time'")
    hist.add_argument("--clear", action="store_true", help="delete all saved history")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    console = Console()

    if args.command == "history":
        store = HistoryStore()
        if args.clear:
            store.clear()
            console.print(f"[green]History cleared[/] ({store.path}).")
        else:
            _show_history(console, store, args.days, args.all)
        return

    console.print(f"[yellow]{AUTH_NOTE}[/]")
    console.print("[grey50]Offline data: DB-IP Country/ASN Lite + OISD small tracker list (bundled in netpulse/data/).[/]")
    history = None
    if not args.no_history:
        try:
            history = HistoryStore()
            console.print(f"[grey50]History: saving findings to {history.path} (disable with --no-history).[/]")
        except Exception as e:  # unwritable folder etc. — run without history rather than not at all
            console.print(f"[yellow]History disabled: {e}[/]")

    try:
        if args.headless:
            asyncio.run(_watch_headless(args.interval, args.min_severity, history))
        else:
            asyncio.run(_watch_dashboard(args.host, args.port, args.interval, console, args.llm, args.min_severity,
                                         history))
    except KeyboardInterrupt:
        console.print("[grey50]stopped.[/]")
    finally:
        if history is not None:
            history.flush()


if __name__ == "__main__":
    main()
