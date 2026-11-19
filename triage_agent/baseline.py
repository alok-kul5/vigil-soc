"""A rule-based triage baseline that uses the same tools as the agent.

This is what a typical SOAR playbook does: look up the alert's indicators,
call it malicious if threat intel says so, take the alert's own severity, and
block whatever looked bad. The evaluation compares the agent against it, so
the agent's numbers have something to beat.
"""

from __future__ import annotations

import re

from .tools import Workspace, load_incident, lookup_asset, lookup_domain, lookup_ip, propose_action, search_attack, search_logs

RULE_TECHNIQUES = {
    "brute force": "T1110.001", "password spray": "T1110.003", "office": "T1204.002", "dns": "T1071.004",
    "recovery": "T1490", "web server": "T1505.003", "port scan": "T1046", "psexec": "T1569.002", "mfa": "T1621",
    "lsass": "T1003.001", "upload": "T1567.002", "mining": "T1496", "powershell": "T1059.001",
    "anonymising": "T1090.003", "log cleared": "T1070.001", "data transfer": "T1048", "travel": "T1078",
}


def triage(incident_id: str) -> dict:
    inc = load_incident(incident_id)
    ws = Workspace(inc)
    alert = inc["alert"]
    ents = alert["entities"]
    ips = [v for k, v in ents.items() if "ip" in k and isinstance(v, str)] + [i for v in ents.values() if isinstance(v, list)
                                                                           for i in v if re.fullmatch(r"[\d.]+", str(i))]
    domains = [v for k, v in ents.items() if k == "domain"]

    bad_ips, bad_domains, evidence = [], [], []
    for ip in ips:
        r = lookup_ip(ws, ip)
        evidence.append(r["record_id"])
        if r["intel"].get("reputation") in ("malicious", "suspicious"):
            bad_ips.append(ip)
    for d in domains:
        r = lookup_domain(ws, d)
        evidence.append(r["record_id"])
        if r["intel"].get("reputation") in ("malicious", "suspicious"):
            bad_domains.append(d)
    for k in ("user", "host"):
        if k in ents:
            r = lookup_asset(ws, ents[k])
            if r.get("record_id"):
                evidence.append(r["record_id"])
    search_logs(ws, text=None)

    # Playbook logic: intel hit or a high-severity rule means malicious.
    malicious = bool(bad_ips or bad_domains) or alert["severity"] == "high"
    techniques = []
    for kw, tid in RULE_TECHNIQUES.items():
        if kw in alert["rule"].lower():
            search_attack(ws, tid)
            techniques.append(tid)
    trig = alert["triggering_event_ids"]
    for ip in bad_ips:
        propose_action(ws, "block_ip", ip, "threat intel hit", trig)
    for d in bad_domains:
        propose_action(ws, "block_domain", d, "threat intel hit", trig)
    if malicious and "host" in ents and alert["severity"] == "high":
        propose_action(ws, "isolate_host", ents["host"], "high-severity alert", trig)

    return {
        "report": {
            "verdict": "true_positive" if malicious else "false_positive",
            "severity": alert["severity"],
            "findings": [{"statement": alert["summary"], "evidence_ids": trig + evidence}],
            "timeline": [], "techniques": [{"id": t, "evidence_ids": trig} for t in techniques],
        },
        "proposals": [{"type": p.type, "target": p.target} for p in ws.proposals],
        "seen_ids": ws.seen_ids,
    }
