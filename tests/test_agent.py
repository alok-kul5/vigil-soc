import json
from dataclasses import replace

import pytest

from triage_agent import actions
from triage_agent.agent import WRAP_UP, TriageAgent, compact
from triage_agent.config import Settings
from triage_agent.tools import load_incident

from .fakes import FakeBackend, down, report, text_turn, tool_turn

INC = "INC-001"


@pytest.fixture
def settings(tmp_path):
    return replace(Settings(), runs_dir=tmp_path / "runs", max_tokens_per_run=100_000, max_seconds_per_run=600)


def ok_event():
    return load_incident(INC)["labels"]["key_evidence"][0]  # the successful login


def test_full_investigation_flow(settings):
    ev = ok_event()
    fake = FakeBackend([
        tool_turn(("search_logs", {"user": "jdoe", "ip": "203.0.113.45", "text": "failure|success"}),
                  ("lookup_ip", {"ip": "203.0.113.45"})),
        tool_turn(("search_attack", {"query": "T1110.001"}),
                  ("propose_action", {"type": "block_ip", "target": "203.0.113.45", "justification": "brute force source",
                                      "evidence_ids": [ev, "TI-IP-203.0.113.45"]})),
        tool_turn(("submit_report", report(findings=[{"statement": "Successful login after 40 failures", "evidence_ids": [ev]}],
                                           techniques=[{"id": "T1110.001", "name": "Password Guessing", "rationale": "40 failures",
                                                        "evidence_ids": [ev]}]))),
    ])
    r = TriageAgent(fake, settings).investigate(INC)

    assert r.status == "completed"
    assert r.report["verdict"] == "true_positive"
    assert [(p["type"], p["target"], p["status"]) for p in r.proposals] == [("block_ip", "203.0.113.45", "pending")]
    assert r.usage.model_calls == 3 and r.usage.total_tokens == 3 * 2300
    assert r.usage.cost_usd == 0.0  # local model

    # The OR search matched both the 40 failures and the success.
    assert json.loads(r.steps[0]["result"])["total_matches"] >= 41
    # Tool results go back as role=tool messages, one per call.
    second = fake.calls[1]["messages"]
    assert [m["role"] for m in second[-2:]] == ["tool", "tool"]
    assert second[0]["role"] == "system"
    assert {t["name"] for t in fake.calls[0]["tools"]} >= {"search_logs", "propose_action", "submit_report"}

    run_dir = settings.runs_dir / r.run_id
    assert json.loads((run_dir / "run.json").read_text())["status"] == "completed"
    spans = [json.loads(line) for line in (run_dir / "trace.jsonl").read_text().splitlines()]
    assert sum(s["name"] == "llm.call" for s in spans) == 3
    assert sum(s["name"] == "tool.call" for s in spans) == 5
    assert spans[-1]["name"] == "investigation" and spans[-1]["attributes"]["status"] == "completed"


def test_invalid_arguments_get_a_helpful_error(settings):
    fake = FakeBackend([tool_turn(("search_logs", {"src_ip": "1.2.3.4"})), text_turn(), text_turn(), text_turn()])
    r = TriageAgent(fake, settings).investigate(INC)
    assert r.steps[0]["is_error"] and "unknown field src_ip" in r.steps[0]["result"]
    assert r.invalid_tool_calls == 1


def test_report_citing_unseen_evidence_is_rejected_then_fixed(settings):
    ev = ok_event()
    fake = FakeBackend([
        tool_turn(("submit_report", report(findings=[{"statement": "made up", "evidence_ids": ["EVT-000000"]}]))),
        tool_turn(("get_event", {"event_id": ev}),
                  ("propose_action", {"type": "open_ticket", "target": "jdoe", "justification": "j", "evidence_ids": [ev]})),
        tool_turn(("submit_report", report(findings=[{"statement": "real", "evidence_ids": [ev]}]))),
    ])
    r = TriageAgent(fake, settings).investigate(INC)
    assert r.status == "completed" and r.rejected_reports == 1
    assert "never returned by a tool" in fake.calls[1]["messages"][-1]["content"]


def test_unknown_attack_id_is_rejected(settings):
    trig = load_incident(INC)["alert"]["triggering_event_ids"][0]
    bad = report(findings=[{"statement": "x", "evidence_ids": [trig]}],
                 techniques=[{"id": "T9999", "name": "Made up", "rationale": "", "evidence_ids": [trig]}])
    r = TriageAgent(FakeBackend([tool_turn(("submit_report", bad)), text_turn(), text_turn(), text_turn()]), settings).investigate(INC)
    assert r.report is None and "unknown ATT&CK" in r.steps[0]["result"]


def test_malicious_verdict_requires_a_proposal(settings):
    ev = ok_event()
    fake = FakeBackend([tool_turn(("get_event", {"event_id": ev}),
                                  ("submit_report", report(findings=[{"statement": "s", "evidence_ids": [ev]}]))),
                        text_turn(), text_turn(), text_turn()])
    r = TriageAgent(fake, settings).investigate(INC)
    assert r.report is None and "needs at least one propose_action" in r.steps[1]["result"]


def test_proposal_must_cite_seen_evidence(settings):
    fake = FakeBackend([
        tool_turn(("propose_action", {"type": "isolate_host", "target": "vpn-gw-01", "justification": "?", "evidence_ids": ["EVT-1"]})),
        text_turn(), text_turn(), text_turn(),
    ])
    r = TriageAgent(fake, settings).investigate(INC)
    assert r.proposals == [] and r.steps[0]["is_error"]


def test_token_budget_warns_then_stops(settings):
    s = replace(settings, max_tokens_per_run=8_000)
    search = ("search_logs", {"text": "jdoe"})
    fake = FakeBackend([tool_turn(search, prompt=3000, completion=500) for _ in range(5)])
    r = TriageAgent(fake, s).investigate(INC)
    assert r.status == "budget_exceeded"
    assert r.usage.model_calls == 3            # 10,500 tokens > 8,000, so no 4th call
    # Crossing 80% (7,000 of 8,000 after call 2) adds a wrap-up system message to the next request.
    assert fake.calls[1]["messages"][-1]["role"] == "tool"
    assert fake.calls[2]["messages"][-1] == {"role": "system", "content": WRAP_UP}


def test_dollar_budget_applies_when_backend_is_priced(settings):
    s = replace(settings, price_in_per_mtok=10.0, price_out_per_mtok=10.0, max_cost_usd=0.05)
    fake = FakeBackend([tool_turn(("search_logs", {"text": "x"}), prompt=2000, completion=500) for _ in range(5)])
    r = TriageAgent(fake, s).investigate(INC)
    assert r.status == "budget_exceeded"
    assert r.usage.cost_usd == pytest.approx(0.05)  # two calls at $0.025


def test_model_that_never_reports_is_nudged_then_stopped(settings):
    fake = FakeBackend([text_turn(), text_turn(), text_turn()])
    r = TriageAgent(fake, settings).investigate(INC)
    assert r.status == "error"
    assert fake.calls[1]["messages"][-1]["content"].startswith("You haven't submitted")


def test_backend_down_is_captured(settings):
    r = TriageAgent(FakeBackend([down()]), settings).investigate(INC)
    assert r.status == "error" and "Ollama" in r.error


def test_labels_never_reach_the_model(settings):
    fake = FakeBackend([down()])
    TriageAgent(fake, settings).investigate("INC-015")
    sent = json.dumps(fake.calls[0]["messages"])
    assert "labels" not in sent and "expected_actions" not in sent


def test_compaction_keeps_ids_and_recent_results():
    msgs = [{"role": "system", "content": "s"}]
    for i in range(5):
        msgs.append({"role": "tool", "tool_name": "search_logs", "content": json.dumps({"events": [{"id": f"EVT-10000{i}"}]})})
    out = compact(msgs, keep=2)
    assert out[1]["content"].startswith("[earlier search_logs result compacted") and "EVT-100000" in out[1]["content"]
    assert out[-1]["content"] == msgs[-1]["content"]
    assert sum(m.get("_compacted", False) for m in out) == 3


def test_approval_flow(settings):
    ev = ok_event()
    fake = FakeBackend([
        tool_turn(("get_event", {"event_id": ev}),
                  ("propose_action", {"type": "block_ip", "target": "203.0.113.45", "justification": "j", "evidence_ids": [ev]}),
                  ("propose_action", {"type": "disable_account", "target": "jdoe", "justification": "j", "evidence_ids": [ev]})),
        tool_turn(("submit_report", report(findings=[{"statement": "s", "evidence_ids": [ev]}]))),
    ])
    r = TriageAgent(fake, settings).investigate(INC)

    with pytest.raises(actions.ApprovalError):
        actions.decide(r.run_id, "ACT-1", approve=True, approver=" ", settings=settings)
    done = actions.decide(r.run_id, "ACT-1", approve=True, approver="Sam", settings=settings)
    assert done["status"] == "executed" and done["result"].startswith("SIMULATED firewall")
    rej = actions.decide(r.run_id, "ACT-2", approve=False, approver="Sam", note="user confirmed travel", settings=settings)
    assert rej["status"] == "rejected"
    with pytest.raises(actions.ApprovalError, match="already"):
        actions.decide(r.run_id, "ACT-1", approve=True, approver="Sam", settings=settings)
    audit = (settings.runs_dir / r.run_id / "audit.log").read_text().splitlines()
    assert [json.loads(line)["decision"] for line in audit] == ["approved", "rejected"]
