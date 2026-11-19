"""Human approval and execution of proposed actions.

The agent can only *propose*. An action runs only after a named person
approves it here, and every decision is written to an append-only audit log.
The connectors are simulated (they log what a real firewall, EDR or identity
provider call would do), so the project can run without real infrastructure.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .config import Settings

CONNECTORS = {
    "block_ip": "firewall: add deny rule for {target} (inbound and outbound)",
    "block_domain": "secure web gateway + DNS: sinkhole {target}",
    "disable_account": "identity provider: disable account {target}",
    "reset_password": "identity provider: force password reset for {target}",
    "revoke_sessions": "identity provider: revoke all sessions and refresh tokens for {target}",
    "isolate_host": "EDR: network-isolate {target} (management channel kept)",
    "kill_process": "EDR: terminate {target} and block its hash",
    "quarantine_email": "mail gateway: purge {target} from all mailboxes",
    "remove_mail_rule": "mail server: delete inbox forwarding rules for {target}",
    "open_ticket": "ticketing: open case for {target}",
}


class ApprovalError(Exception):
    pass


def _run_path(run_id: str, settings: Settings) -> Path:
    path = settings.runs_dir / run_id / "run.json"
    if not path.exists():
        raise ApprovalError(f"unknown run {run_id}")
    return path


def decide(run_id: str, action_id: str, approve: bool, approver: str, note: str = "",
           settings: Settings | None = None) -> dict:
    """Approve (and execute) or reject one proposed action."""
    settings = settings or Settings()
    if not approver.strip():
        raise ApprovalError("an approver name is required")
    path = _run_path(run_id, settings)
    run = json.loads(path.read_text())
    action = next((a for a in run["proposals"] if a["id"] == action_id), None)
    if action is None:
        raise ApprovalError(f"no action {action_id} in run {run_id}")
    if action["status"] != "pending":
        raise ApprovalError(f"{action_id} was already {action['status']}")

    now = datetime.now(UTC).isoformat()
    action.update(decided_by=approver, decided_at=now)
    if approve:
        action["result"] = "SIMULATED " + CONNECTORS[action["type"]].format(target=action["target"])
        action["status"] = "executed"
    else:
        action["status"] = "rejected"
        action["result"] = f"rejected: {note}" if note else "rejected"

    path.write_text(json.dumps(run, indent=2))
    with (path.parent / "audit.log").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"time": now, "run_id": run_id, "action_id": action_id, "type": action["type"],
                            "target": action["target"], "decision": "approved" if approve else "rejected",
                            "approver": approver, "note": note, "result": action["result"]}) + "\n")
    return action
