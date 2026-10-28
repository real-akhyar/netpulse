"""Trust / mute list: apps and domains the user has marked as expected.

- Trusting an **app** takes it out of the Caught list, the timeline and "export everything", and
  stops its process alerts from painting its traffic suspicious.
- Trusting a **domain** (and its subdomains) clears tracker / beacon / malware findings for it —
  for a tracker you're fine with, or a false positive.
- Safety rule: trusting an app never hides a **known-malware** contact. A trusted app that talks to
  listed malware infrastructure is still called out (it may have been compromised since).

Rules persist in trust.json next to the history database — a separate file, so trust works with
--no-history and is easy to read or edit by hand.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class Trust:
    apps: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)

    def covers(self, host: Optional[str]) -> bool:
        """True if host is a trusted domain or a subdomain of one."""
        if not host or not self.domains:
            return False
        labels = host.lower().rstrip(".").split(".")
        return any(".".join(labels[i:]) in self.domains for i in range(len(labels)))

    def covers_any(self, *hosts: Optional[str]) -> bool:
        return any(self.covers(h) for h in hosts)


def default_path() -> Path:
    from netpulse.store import default_path as history_path

    return history_path().with_name("trust.json")


class TrustStore:
    """Loads/saves trust rules; `.trust` is the live object the ranker reads."""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_path()
        self.trust = Trust()
        self.notes: dict[tuple[str, str], dict] = {}  # (kind, value) -> {"added": ts, "name": label}
        self._load()

    def _load(self) -> None:
        try:
            rules = json.loads(self.path.read_text(encoding="utf-8")).get("rules", [])
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            log.warning("trust list unreadable (%s); starting empty", self.path)
            return
        for rule in rules:
            kind, value = rule.get("kind"), rule.get("value")
            if kind in ("app", "domain") and isinstance(value, str) and value:
                self._set(kind, value, rule.get("name") or value, rule.get("added") or time.time())

    def _set(self, kind: str, value: str, name: str, added: float) -> None:
        (self.trust.apps if kind == "app" else self.trust.domains).add(value)
        self.notes[(kind, value)] = {"added": added, "name": name}

    def _save(self) -> None:
        rules = [{"kind": k, "value": v, **meta} for (k, v), meta in sorted(self.notes.items())]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replace: a crash mid-write never leaves a half-written file.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".trust-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"rules": rules}, f, indent=2)
        os.replace(tmp, self.path)

    def add(self, kind: str, value: str, name: Optional[str] = None) -> None:
        self._set(kind, value, name or value, time.time())
        self._save()

    def remove(self, kind: str, value: str) -> bool:
        if (kind, value) not in self.notes:
            return False
        del self.notes[(kind, value)]
        (self.trust.apps if kind == "app" else self.trust.domains).discard(value)
        self._save()
        return True

    def rules(self) -> list[dict]:
        return [{"kind": k, "value": v, **meta} for (k, v), meta in sorted(self.notes.items(), key=lambda kv: -kv[1]["added"])]

    def clear(self) -> None:
        self.notes.clear()
        self.trust.apps.clear()
        self.trust.domains.clear()
        self._save()
