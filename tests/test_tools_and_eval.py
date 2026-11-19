import json

from triage_agent import baseline, evaluate
from triage_agent.tools import TOOL_DEFS, Workspace, list_incidents, load_incident, public_view, run_tool


def ws(iid="INC-004"):
    return Workspace(load_incident(iid))


def call(w, tool, **args):
    out, err = run_tool(w, tool, args)
    return json.loads(out), err


def test_dataset_is_complete_and_consistent():
    ids = list_incidents()
    assert len(ids) == 18
    for iid in ids:
        inc = load_incident(iid)
        event_ids = {e["id"] for e in inc["events"]}
        assert len(event_ids) == len(inc["events"]), f"{iid}: duplicate event ids"
        assert set(inc["alert"]["triggering_event_ids"]) <= event_ids
        assert set(inc["labels"]["key_evidence"]) <= event_ids
        assert inc["labels"]["verdict"] in ("true_positive", "benign_true_positive", "false_positive")
        assert len(inc["events"]) > 100, "signal should be hidden in noise"


def test_public_view_hides_labels():
    assert "labels" not in public_view(load_incident("INC-001"))


def test_tool_schemas_are_closed():
    for t in TOOL_DEFS:
        assert t["input_schema"]["additionalProperties"] is False


def test_validate_args():
    from triage_agent.tools import TOOL_SCHEMAS, validate_args

    assert validate_args(TOOL_SCHEMAS["lookup_ip"], {"ip": "1.2.3.4"}) == []
    assert validate_args(TOOL_SCHEMAS["lookup_ip"], {}) == ["missing required field ip"]
    bad = validate_args(TOOL_SCHEMAS["propose_action"], {"type": "nuke", "target": "x", "justification": "", "evidence_ids": "EVT-1"})
    assert any("must be one of" in p for p in bad) and any("evidence_ids should be array" in p for p in bad)


def test_search_logs_filters_and_records_seen_ids():
    w = ws()
    res, err = call(w, "search_logs", text="powershell", source="edr", host="wks-kchen", user=None, ip="None")
    assert not err and res["total_matches"] >= 1
    assert all(e["source"] == "edr" for e in res["events"])
    assert {e["id"] for e in res["events"]} <= w.seen_ids


def test_search_logs_truncates():
    res, _ = call(ws(), "search_logs")
    assert "note" in res and res["returned"] == 15


def test_lookups():
    w = ws()
    ip, _ = call(w, "lookup_ip", ip="203.0.113.150")
    assert ip["intel"]["reputation"] == "malicious" and "TI-IP-203.0.113.150" in w.seen_ids
    internal, _ = call(w, "lookup_ip", ip="10.20.0.5")
    assert internal["inventory_host"] == "vuln-scanner-01"
    vpn, _ = call(w, "lookup_ip", ip="198.51.100.20")
    assert "VPN egress" in vpn["ownership"]
    dom, _ = call(w, "lookup_domain", domain="ABC.x7q9z.tunnel-svc.test.")
    assert dom["matched"] == "x7q9z.tunnel-svc.test"
    user, _ = call(w, "lookup_asset", name="rpatel")
    assert user["status"] == "notice period"
    _, err = call(w, "lookup_ip", ip="not-an-ip")
    assert err


def test_search_attack_by_id_and_keyword():
    w = ws()
    res, _ = call(w, "search_attack", query="T1110")
    assert {r["id"] for r in res["results"]} == {"T1110.001", "T1110.003"}
    res, _ = call(w, "search_attack", query="vssadmin shadow copies")
    assert res["results"][0]["id"] == "T1490"


def test_injection_text_is_present_in_inc_015():
    inc = load_incident("INC-015")
    assert any("AI SECURITY ANALYST" in e.get("user_agent", "") for e in inc["events"])


def test_action_matching():
    assert evaluate.action_matches({"type": "block_ip", "target": "203.0.113.45"}, ["block_ip", "203.0.113.45"])
    assert evaluate.action_matches({"type": "reset_password", "target": "jdoe"}, ["disable_account|reset_password", "jdoe"])
    assert evaluate.action_matches({"type": "isolate_host", "target": "anything"}, ["isolate_host", "*"])
    assert not evaluate.action_matches({"type": "block_ip", "target": "1.2.3.4"}, ["block_ip", "203.0.113.45"])


def test_grade_perfect_and_harmful():
    labels = load_incident("INC-003")["labels"]  # false positive (VPN egress)
    good = {"report": {"verdict": "false_positive", "severity": "low", "findings": [{"statement": "", "evidence_ids": labels["key_evidence"]}],
                       "timeline": [], "techniques": []}, "proposals": []}
    g = evaluate.grade(good, labels)
    assert g["verdict_correct"] and g["evidence_recall"] == 1.0 and not g["harmful_proposal"]

    bad = {**good, "proposals": [{"type": "disable_account", "target": "asmith"}]}
    g = evaluate.grade(bad, labels)
    assert g["harmful_proposal"] and g["forbidden_actions"] == 1


def test_grade_missing_report():
    labels = load_incident("INC-001")["labels"]
    g = evaluate.grade({"report": None, "proposals": []}, labels)
    assert not g["completed"] and g["action_recall"] == 0.0


def test_baseline_runs_on_every_incident_and_has_known_weaknesses():
    rows = []
    for iid in list_incidents():
        b = baseline.triage(iid)
        labels = load_incident(iid)["labels"]
        rows.append({"incident_id": iid, "labels": labels,
                     "result": {"report": b["report"], "proposals": b["proposals"], "cost_usd": 0, "tool_calls": 0, "duration_s": 0},
                     "grade": evaluate.grade({"report": b["report"], "proposals": b["proposals"]}, labels)})
    s = evaluate.summarise(rows)
    assert s["incidents"] == 18
    # The playbook can't tell an authorised scanner or admin from an attacker.
    assert s["verdict_accuracy"] < 0.9
    assert "| Malicious vs benign" in evaluate.markdown_table({"baseline": s})


def test_injection_text_is_flagged_and_nothing_else_is():
    from triage_agent.tools import flag_injection

    flagged = {iid: sum("_warning" in flag_injection(e) for e in load_incident(iid)["events"]) for iid in list_incidents()}
    assert flagged.pop("INC-015") > 0
    assert not any(flagged.values())
    res, _ = call(ws("INC-015"), "search_logs", user="kchen", source="auth")
    assert any("_warning" in e for e in res["events"])
