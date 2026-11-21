from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from triage_agent.agent import TriageAgent
from triage_agent.tools import load_incident
from triage_agent.web import app as web

from .fakes import FakeBackend, report, tool_turn


@pytest.fixture
def client(tmp_path, monkeypatch):
    s = replace(web.settings, runs_dir=tmp_path / "runs")
    monkeypatch.setattr(web, "settings", s)
    monkeypatch.setattr(web, "_api_available", lambda: False)  # as if Ollama isn't running
    return TestClient(web.app), s


def make_run(settings):
    ev = load_incident("INC-001")["labels"]["key_evidence"][0]
    fake = FakeBackend([
        tool_turn(("get_event", {"event_id": ev}),
                  ("propose_action", {"type": "block_ip", "target": "203.0.113.45", "justification": "j", "evidence_ids": [ev]})),
        tool_turn(("submit_report", report(findings=[{"statement": "s", "evidence_ids": [ev]}]))),
    ])
    return TriageAgent(fake, settings).investigate("INC-001")


def test_queue_hides_labels_and_shows_latest_run(client):
    c, s = client
    run = make_run(s)
    rows = c.get("/api/incidents").json()
    assert len(rows) == 18
    assert all("labels" not in r and "events" not in r for r in rows)
    first = next(r for r in rows if r["id"] == "INC-001")
    assert first["latest_run"]["run_id"] == run.run_id
    assert first["latest_run"]["pending_actions"] == 1


def test_investigate_without_model_is_503(client):
    c, _ = client
    assert c.get("/api/health").json()["api_configured"] is False
    assert c.post("/api/incidents/INC-001/investigate").status_code == 503


def test_approve_via_api_and_trace(client):
    c, s = client
    run = make_run(s)
    bad = c.post(f"/api/runs/{run.run_id}/actions/ACT-1", json={"decision": "approve", "approver": ""})
    assert bad.status_code == 422
    ok = c.post(f"/api/runs/{run.run_id}/actions/ACT-1", json={"decision": "approve", "approver": "Sam"})
    assert ok.status_code == 200 and ok.json()["status"] == "executed"
    again = c.post(f"/api/runs/{run.run_id}/actions/ACT-1", json={"decision": "reject", "approver": "Sam"})
    assert again.status_code == 400
    assert any(sp["name"] == "llm.call" for sp in c.get(f"/api/runs/{run.run_id}/trace").json())


def test_event_lookup_and_page(client):
    c, _ = client
    ev = load_incident("INC-001")["events"][0]["id"]
    assert c.get(f"/api/incidents/INC-001/events/{ev}").json()["id"] == ev
    assert c.get("/api/incidents/INC-001/events/EVT-0").status_code == 404
    assert "Vigil" in c.get("/").text
