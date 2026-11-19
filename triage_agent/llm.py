"""The model backend: a local model served by Ollama.

Kept behind a tiny interface (`chat(messages, tools) -> Turn`) so the agent
loop doesn't care where the model runs, and tests can swap in a scripted fake.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from .config import Settings


@dataclass
class ToolCall:
    id: str
    name: str
    args: dict


@dataclass
class Turn:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    thinking: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    done_reason: str = "stop"
    model: str = ""


class Backend(Protocol):
    model: str

    def chat(self, messages: list[dict], tools: list[dict]) -> Turn: ...


class BackendError(Exception):
    pass


class OllamaBackend:
    def __init__(self, settings: Settings, timeout: float = 300) -> None:
        self.s = settings
        self.model = settings.model
        self._http = httpx.Client(base_url=settings.ollama_url, timeout=timeout)

    def available(self) -> bool:
        try:
            tags = self._http.get("/api/tags", timeout=3).json()
        except (httpx.HTTPError, ValueError):
            return False
        return any(m["name"] == self.model or m["name"] == f"{self.model}:latest" for m in tags.get("models", []))

    def chat(self, messages: list[dict], tools: list[dict]) -> Turn:
        body = {
            "model": self.model,
            "messages": messages,
            "tools": [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                         "parameters": t["input_schema"]}} for t in tools],
            "stream": False,
            "think": self.s.think,
            "options": {"num_ctx": self.s.num_ctx, "temperature": self.s.temperature, "top_p": 0.95, "seed": self.s.seed},
        }
        try:
            r = self._http.post("/api/chat", json=body)
        except httpx.HTTPError as exc:
            raise BackendError(f"could not reach Ollama at {self.s.ollama_url}: {exc}") from exc
        if r.status_code != 200:
            raise BackendError(f"Ollama returned {r.status_code}: {r.text[:300]}")
        data = r.json()
        msg = data.get("message", {})
        calls = []
        for c in msg.get("tool_calls") or []:
            fn = c.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):  # some models return a JSON string
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_unparseable": args}
            calls.append(ToolCall(id=c.get("id") or f"call_{uuid.uuid4().hex[:8]}", name=fn.get("name", ""), args=args or {}))
        return Turn(
            content=msg.get("content", "") or "",
            tool_calls=calls,
            thinking=msg.get("thinking", "") or "",
            prompt_tokens=data.get("prompt_eval_count", 0) or 0,
            completion_tokens=data.get("eval_count", 0) or 0,
            done_reason=data.get("done_reason", "stop"),
            model=data.get("model", self.model),
        )
