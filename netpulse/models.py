"""Canonical API-boundary models (SPEC §3)."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, computed_field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
Scope = Literal["public", "private", "loopback"]
Category = Literal["normal", "tracker", "suspicious", "malware", "local"]


class Flag(BaseModel):
    id: str
    severity: Severity
    title: str
    detail: str = ""


class Connection(BaseModel):
    id: str
    pid: Optional[int] = None
    process_name: str = "unknown"
    process_exe: Optional[str] = None
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    scope: Scope
    # Enrichment (Phase 2) — None until resolved.
    remote_host: Optional[str] = None
    remote_domain: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    category: Category = "normal"
    tracker_rule: Optional[str] = None
    threat_indicator: Optional[str] = None  # listed malware domain/IP this connection matched
    threat: Optional[str] = None  # e.g. "listed as QakBot botnet server by Feodo Tracker (abuse.ch)"
    flags: list[Flag] = Field(default_factory=list)
    first_seen: float
    last_seen: float
    hit_count: int = 1

    @computed_field
    @property
    def app(self) -> str:
        """Aggregation key: culprits are grouped by app (exe, fallback name), never by pid."""
        return self.process_exe or self.process_name


SignatureStatus = Literal["valid", "unsigned", "invalid", "unknown", "checking"]


class ProcessInfo(BaseModel):
    """Who an app is and how it was started — shown in the detail view."""

    pid: int
    exe: Optional[str] = None
    cmdline: Optional[str] = None  # secrets in --token=… style args are redacted
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    started: Optional[float] = None
    user: Optional[str] = None
    signature: SignatureStatus = "unknown"
    signer: Optional[str] = None


class ProcessAgg(BaseModel):
    app: str  # same key as Connection.app — links a culprit to its connections
    pid: Optional[int] = None
    name: str
    exe: Optional[str] = None
    connection_count: int = 0
    distinct_remotes: int = 0
    distinct_countries: int = 0
    tracker_count: int = 0
    suspicious_count: int = 0
    alert_count: int = 0  # suspicious-process alerts (medium+) about who the app is
    malware_count: int = 0  # distinct known-malware domains/IPs contacted
    malware: list[str] = Field(default_factory=list)  # "indicator — description", up to 5
    nosiness: float = 0
    verdict_text: str = ""
    top_trackers: list[str] = Field(default_factory=list)
    flags: list[Flag] = Field(default_factory=list)  # process-level, e.g. many_trackers
    severity: Optional[Severity] = None  # worst non-info finding across the app's connections
    info: Optional[ProcessInfo] = None  # most recent process of this app that we inspected
