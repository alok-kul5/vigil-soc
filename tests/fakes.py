"""A scripted stand-in for the model backend."""

from __future__ import annotations

from triage_agent.llm import BackendError, ToolCall, Turn


def tool_turn(*calls, prompt=2000, completion=300):
    """calls: (name, args) pairs."""
    return Turn(content="", tool_calls=[ToolCall(f"c{i}", n, a) for i, (n, a) in enumerate(calls)],
                prompt_tokens=prompt, completion_tokens=completion, model="fake")


def text_turn(text="Done.", prompt=2000, completion=100):
    return Turn(content=text, prompt_tokens=prompt, completion_tokens=completion, model="fake")


class FakeBackend:
    model = "fake"

    def __init__(self, turns):
        self.turns = list(turns)
        self.calls: list[dict] = []

    def chat(self, messages, tools):
        self.calls.append({"messages": [dict(m) for m in messages], "tools": tools})
        if not self.turns:
            raise AssertionError("FakeBackend ran out of scripted turns")
        nxt = self.turns.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def down():
    return BackendError("could not reach Ollama")


def report(**over):
    base = {
        "verdict": "true_positive", "severity": "high", "confidence": "high",
        "summary": "Brute force then success.",
        "timeline": [], "findings": [{"statement": "x", "evidence_ids": []}],
        "techniques": [], "next_steps": [],
    }
    base.update(over)
    return base
