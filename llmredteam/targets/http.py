from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from ..models import TargetResponse
from .base import ScopeError, Target

_TOOLS = [
    ("send_email", "Send an email on behalf of the user"),
    ("read_file", "Read a file from the server filesystem"),
    ("delete_record", "Delete a customer record"),
]
DEFAULT_TOOLS = [
    {"type": "function", "function": {
        "name": n, "description": d,
        "parameters": {"type": "object", "properties": {}, "additionalProperties": True}}}
    for n, d in _TOOLS
]


class HttpTarget(Target):
    """Any OpenAI-compatible /chat/completions endpoint (a model, your app, or LLMGuard)."""

    def __init__(self, base_url: str, model: str, api_key_env: str | None = None,
                 system_prompt: str = "", tools: bool = False, allowed_hosts: list | None = None,
                 block_status_codes: list | None = None, timeout: float = 60.0):
        host = urlparse(base_url).hostname
        allowed = allowed_hosts or ["localhost", "127.0.0.1"]
        if host not in allowed:
            raise ScopeError(
                f"Host '{host}' is not in allowed_hosts {allowed}. "
                "Only test systems you own or are authorised to test."
            )
        self.name = f"http:{host}"
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.system_prompt = system_prompt
        self.tools = tools
        self.block_codes = set(block_status_codes or [403, 451])
        headers = {"Content-Type": "application/json"}
        if api_key_env and os.environ.get(api_key_env):
            headers["Authorization"] = f"Bearer {os.environ[api_key_env]}"
        self.client = httpx.Client(headers=headers, timeout=timeout)

    def send(self, prompt: str, context_docs: list | None = None) -> TargetResponse:
        user = prompt
        if context_docs:
            ctx = "\n\n".join(f"<document>\n{d}\n</document>" for d in context_docs)
            user = f"Use the following retrieved documents to answer.\n{ctx}\n\nUser question: {prompt}"
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user})
        payload = {"model": self.model, "messages": messages}
        if self.tools:
            payload["tools"] = DEFAULT_TOOLS
        try:
            r = self.client.post(f"{self.base_url}/chat/completions", json=payload)
        except httpx.HTTPError as e:
            return TargetResponse(error=f"{type(e).__name__}: {e}")
        if r.status_code in self.block_codes:
            return TargetResponse(text=r.text[:300], blocked=True)
        if r.status_code >= 400:
            return TargetResponse(error=f"HTTP {r.status_code}: {r.text[:200]}")
        try:
            msg = r.json()["choices"][0]["message"]
        except Exception as e:  # malformed / non-OpenAI response
            return TargetResponse(error=f"Unexpected response shape: {e}")
        calls = [{"name": (tc.get("function") or {}).get("name"),
                  "args": (tc.get("function") or {}).get("arguments")}
                 for tc in (msg.get("tool_calls") or [])]
        return TargetResponse(text=msg.get("content") or "", tool_calls=calls)
