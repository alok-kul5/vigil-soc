"""A small span tracer: every model call and tool call becomes a JSON line.

Traces are written to runs/<run_id>/trace.jsonl and shown in the web UI. The
format (trace_id, span_id, parent_id, name, start/end, attributes) maps
directly onto OpenTelemetry spans if you want to export them later.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("triage")


class Tracer:
    def __init__(self, path: Path | None, trace_id: str) -> None:
        self.path = path
        self.trace_id = trace_id
        self.spans: list[dict] = []
        self._stack: list[str] = []

    @contextmanager
    def span(self, name: str, **attrs):
        span = {
            "trace_id": self.trace_id,
            "span_id": uuid.uuid4().hex[:16],
            "parent_id": self._stack[-1] if self._stack else None,
            "name": name,
            "start": time.time(),
            "attributes": dict(attrs),
            "status": "ok",
        }
        self._stack.append(span["span_id"])
        try:
            yield span["attributes"]
        except Exception as exc:
            span["status"] = "error"
            span["attributes"]["error"] = repr(exc)
            raise
        finally:
            self._stack.pop()
            span["end"] = time.time()
            span["duration_ms"] = round((span["end"] - span["start"]) * 1000, 1)
            self.spans.append(span)
            self._write(span)
            log.info("%s %s %.0fms %s", self.trace_id[:8], name, span["duration_ms"],
                     {k: v for k, v in span["attributes"].items() if k in ("tool", "cost_usd", "is_error", "stop_reason")})

    def _write(self, span: dict) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(span, default=str) + "\n")
