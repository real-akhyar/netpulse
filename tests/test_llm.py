"""Optional LLM explainer: off by default, opt-in rules, parsing, and both provider shapes
against a fake local server (no real API is ever called)."""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from netpulse.llm import client


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    import os
    for var in list(os.environ):
        if var.startswith("NETPULSE_LLM_") or var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            monkeypatch.delenv(var)


def test_off_by_default_even_with_a_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert client.load_config(False) is None
    c = client.load_config(True)
    assert c and c.provider == "anthropic" and c.model == "claude-haiku-5-5"


def test_flag_without_key_stays_off():
    assert client.load_config(True) is None


def test_env_provider(monkeypatch):
    monkeypatch.setenv("NETPULSE_LLM_PROVIDER", "openai")
    monkeypatch.setenv("NETPULSE_LLM_API_KEY", "k2")
    monkeypatch.setenv("NETPULSE_LLM_BASE_URL", "https://x.openai.azure.com/openai/v1/")
    c = client.load_config(False)
    assert c and c.provider == "openai" and c.base_url.endswith("/v1")
    monkeypatch.setenv("NETPULSE_LLM_PROVIDER", "none")
    assert client.load_config(True) is None


def test_parsing():
    d = ["doubleclick.net", "hotjar.com"]
    assert client.parse_explanations('```json\n{"doubleclick.net": "Google ads."}\n```', d) == {"doubleclick.net": "Google ads."}
    assert client.parse_explanations('{"evil.com": "x", "hotjar.com": 5, "doubleclick.net": "a"}', d) == {"doubleclick.net": "a"}
    assert client.parse_explanations("sorry, I can't", d) == {}
    long = client.parse_explanations(json.dumps({"hotjar.com": "x" * 999}), d)["hotjar.com"]
    assert len(long) == client.MAX_SENTENCE


@pytest.fixture
def fake_provider():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            if self.path.endswith("/v1/messages"):
                domains = json.loads(body["messages"][0]["content"])
                reply = {"content": [{"type": "text", "text": json.dumps({x: f"{x} tracks you." for x in domains})}]}
            elif self.path.endswith("/chat/completions"):
                domains = json.loads(body["messages"][1]["content"])
                reply = {"choices": [{"message": {"content": json.dumps({x: f"{x} (oai)" for x in domains})}}]}
            else:
                self.send_response(500)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen
    srv.shutdown()


def test_anthropic_round_trip(fake_provider):
    base, seen = fake_provider

    async def go():
        ex = client.Explainer(client.LLMConfig("anthropic", "secret-key", "claude-haiku-5-5", base))
        out = await ex.explain(["doubleclick.net", "hotjar.com"])
        assert out == {"doubleclick.net": "doubleclick.net tracks you.", "hotjar.com": "hotjar.com tracks you."}
        _, headers, body = seen[-1]
        assert headers.get("x-api-key") == "secret-key" and body["model"] == "claude-haiku-5-5" and "system" in body
        assert json.loads(body["messages"][0]["content"]) == ["doubleclick.net", "hotjar.com"]  # only domain names
        n = len(seen)
        await ex.explain(["doubleclick.net"])
        assert len(seen) == n  # cached
    asyncio.run(go())


def test_openai_compatible_round_trip(fake_provider):
    base, seen = fake_provider

    async def go():
        ex = client.Explainer(client.LLMConfig("openai", "k3", "gpt-x", base + "/v1"))
        assert await ex.explain(["criteo.com"]) == {"criteo.com": "criteo.com (oai)"}
        assert seen[-1][1].get("authorization") == "Bearer k3"
    asyncio.run(go())


def test_unreachable_provider_returns_empty():
    async def go():
        dead = client.Explainer(client.LLMConfig("anthropic", "k", "m", "http://127.0.0.1:9"))
        assert await dead.explain(["a.com"]) == {}
    asyncio.run(go())
