"""Optional one-sentence "what is this tracker" explainer (SPEC §7). OFF by default.

Enabled only by `--llm` or NETPULSE_LLM_PROVIDER. Sends tracker *domain names only* — never
anything about this machine. Batched, strict JSON, defensively parsed; any failure just means
no explanation (the rule-based verdicts already stand). Plain HTTPS via urllib: no SDK dependency.

Env: NETPULSE_LLM_PROVIDER (anthropic|openai|none), NETPULSE_LLM_API_KEY, NETPULSE_LLM_MODEL,
NETPULSE_LLM_BASE_URL (OpenAI-compatible / Azure endpoints). Falls back to ANTHROPIC_API_KEY /
OPENAI_API_KEY for auto-detection.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

DEFAULTS = {
    "anthropic": {"model": "claude-haiku-5-5", "base_url": "https://api.anthropic.com"},
    "openai": {"model": "gpt-4o-mini", "base_url": "https://api.openai.com/v1"},
}
PROVIDER_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
BATCH_SIZE = 20
TIMEOUT = 20.0
MAX_SENTENCE = 280

SYSTEM_PROMPT = (
    "You explain internet tracking domains to non-technical people. For each domain you are given, "
    "write ONE plain-English sentence: who operates it and what it collects or does (ads, analytics, "
    "telemetry, session recording...). Be concrete and calm, no jargon. If you are not sure, say what "
    "kind of service it most likely is rather than inventing specifics. "
    'Reply with ONLY a JSON object mapping each domain to its sentence, e.g. {"doubleclick.net": "..."}.'
)


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    api_key: str
    model: str
    base_url: str

    def describe(self) -> str:
        return f"{self.provider} ({self.model})"


def load_config(requested: bool) -> Optional[LLMConfig]:
    """None unless the user opted in (flag or env) AND a usable key exists."""
    provider = os.environ.get("NETPULSE_LLM_PROVIDER", "").strip().lower()
    if provider in ("none", "off"):
        return None
    if not requested and not provider:
        return None
    key = os.environ.get("NETPULSE_LLM_API_KEY", "").strip()
    if not provider:
        provider = next((p for p, env in PROVIDER_KEY_ENV.items() if os.environ.get(env)), "")
    if provider not in DEFAULTS:
        log.warning("LLM explainer: unknown or undetectable provider %r - staying off", provider)
        return None
    key = key or os.environ.get(PROVIDER_KEY_ENV[provider], "").strip()
    if not key:
        log.warning("LLM explainer: no API key for %s - staying off", provider)
        return None
    return LLMConfig(
        provider=provider,
        api_key=key,
        model=os.environ.get("NETPULSE_LLM_MODEL", "").strip() or DEFAULTS[provider]["model"],
        base_url=(os.environ.get("NETPULSE_LLM_BASE_URL", "").strip() or DEFAULTS[provider]["base_url"]).rstrip("/"),
    )


def parse_explanations(text: str, domains: list[str]) -> dict[str, str]:
    """Pull the JSON object out of a model reply; keep only requested domains with string values."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    wanted = set(domains)
    out = {}
    for domain, sentence in data.items():
        if domain in wanted and isinstance(sentence, str) and sentence.strip():
            out[domain] = " ".join(sentence.split())[:MAX_SENTENCE]
    return out


class Explainer:
    def __init__(self, config: LLMConfig):
        self.config = config
        self._cache: dict[str, str] = {}

    async def explain(self, domains: list[str]) -> dict[str, str]:
        todo = [d for d in dict.fromkeys(domains) if d not in self._cache]
        for i in range(0, len(todo), BATCH_SIZE):
            batch = todo[i : i + BATCH_SIZE]
            try:
                reply = await asyncio.to_thread(self._complete, json.dumps(batch))
                self._cache.update(parse_explanations(reply, batch))
            except Exception as e:  # network, auth, quota, bad JSON — all non-fatal
                log.warning("LLM explainer request failed (%s); continuing without it", type(e).__name__)
        return {d: self._cache[d] for d in domains if d in self._cache}

    # ---- providers (blocking; called in a worker thread) -----------------

    def _complete(self, user_content: str) -> str:
        if self.config.provider == "anthropic":
            return self._anthropic(user_content)
        return self._openai(user_content)

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def _anthropic(self, user_content: str) -> str:
        data = self._post(
            f"{self.config.base_url}/v1/messages",
            {"x-api-key": self.config.api_key, "anthropic-version": "2023-06-01"},
            {
                "model": self.config.model,
                "max_tokens": 1500,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_content}],
            },
        )
        return "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")

    def _openai(self, user_content: str) -> str:
        headers = {"authorization": f"Bearer {self.config.api_key}"}
        if (urllib.parse.urlparse(self.config.base_url).hostname or "").endswith(".azure.com"):
            headers["api-key"] = self.config.api_key  # Azure OpenAI auth header
        data = self._post(
            f"{self.config.base_url}/chat/completions",
            headers,
            {
                "model": self.config.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
            },
        )
        return data["choices"][0]["message"]["content"] or ""
