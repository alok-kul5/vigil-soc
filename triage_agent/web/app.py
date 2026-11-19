"""FastAPI service: alert queue, investigations, approvals and traces."""

from __future__ import annotations

import json
import logging
import shutil
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import actions
from ..config import ROOT, Settings
from ..tools import list_incidents, load_incident, public_view

log = logging.getLogger("triage.web")
STATIC = Path(__file__).parent / "static"
EXAMPLES = ROOT / "examples" / "runs"

settings = Settings()
app = FastAPI(title="Security Alert Triage Agent", version="1.0.0")
_running: dict[str, str] = {}   # run_id -> incident_id
_lock = threading.Lock()


def _seed_examples() -> None:
    """Show recorded example runs on a fresh install (no API key needed to look around)."""
    if EXAMPLES.exists() and not any(settings.runs_dir.glob("*/run.json")):
        settings.runs_dir.mkdir(parents=True, exist_ok=True)
        for d in EXAMPLES.iterdir():
            if d.is_dir():
                shutil.copytree(d, settings.runs_dir / d.name, dirs_exist_ok=True)


_seed_examples()


def _runs() -> list[dict]:
    out = []
    for p in settings.runs_dir.glob("*/run.json"):
        try:
            r = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        out.append(r)
    return sorted(out, key=lambda r: r["started_at"], reverse=True)


def _api_available() -> bool:
    from ..llm import OllamaBackend

    return OllamaBackend(settings).available()


@app.get("/api/health")
def health():
    return {"status": "ok", "model": settings.model, "api_configured": _api_available(), "running": len(_running)}


@app.get("/api/incidents")
def incidents():
    runs = _runs()
    out = []
    for iid in list_incidents():
        inc = public_view(load_incident(iid))
        latest = next((r for r in runs if r["incident_id"] == iid), None)
        running = iid in _running.values()
        out.append({**inc, "latest_run": latest and {
            "run_id": latest["run_id"], "status": latest["status"],
            "verdict": (latest.get("report") or {}).get("verdict"), "severity": (latest.get("report") or {}).get("severity"),
            "pending_actions": sum(a["status"] == "pending" for a in latest["proposals"]),
        }, "running": running})
    return out


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    try:
        inc = load_incident(incident_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {**public_view(inc), "event_count": len(inc["events"]),
            "runs": [r["run_id"] for r in _runs() if r["incident_id"] == incident_id]}


@app.get("/api/incidents/{incident_id}/events/{event_id}")
def event(incident_id: str, event_id: str):
    inc = load_incident(incident_id)
    for e in inc["events"]:
        if e["id"] == event_id:
            return e
    raise HTTPException(404, "no such event")


@app.post("/api/incidents/{incident_id}/investigate", status_code=202)
def investigate(incident_id: str):
    if incident_id not in list_incidents():
        raise HTTPException(404, "unknown incident")
    if not _api_available():
        raise HTTPException(503, f"The model {settings.model} isn't available on the server (is Ollama running?).")
    with _lock:
        if incident_id in _running.values():
            raise HTTPException(409, "an investigation of this incident is already running")
        import uuid

        run_id = f"{incident_id}-{uuid.uuid4().hex[:8]}"
        _running[run_id] = incident_id

    def work():
        from ..agent import TriageAgent
        from ..llm import OllamaBackend

        try:
            TriageAgent(OllamaBackend(settings), settings).investigate(incident_id, run_id=run_id)
        except Exception:
            log.exception("investigation %s failed", run_id)
        finally:
            _running.pop(run_id, None)

    threading.Thread(target=work, daemon=True).start()
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}")
def run(run_id: str):
    path = settings.runs_dir / run_id / "run.json"
    if path.exists():
        return json.loads(path.read_text())
    if run_id in _running:
        return {"run_id": run_id, "incident_id": _running[run_id], "status": "running"}
    raise HTTPException(404, "unknown run")


@app.get("/api/runs/{run_id}/trace")
def trace(run_id: str):
    path = settings.runs_dir / run_id / "trace.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class Decision(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    approver: str = Field(min_length=1, max_length=80)
    note: str = Field("", max_length=500)


@app.post("/api/runs/{run_id}/actions/{action_id}")
def decide(run_id: str, action_id: str, d: Decision):
    try:
        return actions.decide(run_id, action_id, approve=d.decision == "approve", approver=d.approver, note=d.note,
                              settings=settings)
    except actions.ApprovalError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/eval")
def eval_results():
    out = {}
    for p in sorted((ROOT / "eval" / "results").glob("*.json")):
        data = json.loads(p.read_text())
        out[data["name"]] = data["summary"]  # later files win: latest run per name
    return out


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
