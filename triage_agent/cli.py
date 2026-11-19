"""Command line: investigate, evaluate, approve, serve.

    python -m triage_agent.cli investigate INC-004
    python -m triage_agent.cli eval --baseline-only
    python -m triage_agent.cli eval
    python -m triage_agent.cli approve <run_id> ACT-1 --by "Sam Okafor"
    python -m triage_agent.cli serve
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace

from . import actions, baseline, evaluate
from .config import ROOT, Settings
from .tools import list_incidents, load_incident


def _backend(settings: Settings):
    from .llm import OllamaBackend

    b = OllamaBackend(settings)
    if not b.available():
        sys.exit(f"Model {settings.model} is not available at {settings.ollama_url}. Install Ollama, then: ollama pull {settings.model}")
    return b


def cmd_investigate(a) -> int:
    from .agent import TriageAgent

    s = Settings()
    r = TriageAgent(_backend(s), s).investigate(a.incident)
    print(json.dumps({"run_id": r.run_id, "status": r.status, "tokens": r.usage.total_tokens, "seconds": r.duration_s,
                      "verdict": (r.report or {}).get("verdict"), "severity": (r.report or {}).get("severity"),
                      "proposals": [(p["id"], p["type"], p["target"]) for p in r.proposals], "error": r.error}, indent=2))
    if r.report:
        print("\n" + r.report["summary"])
    return 0 if r.status == "completed" else 1


def _agent_row(agent, iid: str) -> dict:
    r = agent.investigate(iid)
    return {
        "incident_id": iid,
        "result": {"status": r.status, "report": r.report, "proposals": r.proposals, "cost_usd": r.usage.cost_usd,
                   "tokens": r.usage.total_tokens, "tool_calls": len(r.steps), "duration_s": r.duration_s, "run_id": r.run_id,
                   "rejected_reports": r.rejected_reports, "invalid_tool_calls": r.invalid_tool_calls, "error": r.error},
    }


def cmd_eval(a) -> int:
    ids = a.incidents or list_incidents()
    summaries, out_dir = {}, ROOT / "eval" / "results"

    rows = []
    for iid in ids:
        b = baseline.triage(iid)
        rows.append({"incident_id": iid, "result": {"status": "completed", "report": b["report"], "proposals": b["proposals"],
                                                    "cost_usd": 0.0, "tool_calls": 0, "duration_s": 0.0}})
    for row in rows:
        row["labels"] = load_incident(row["incident_id"])["labels"]
        row["grade"] = evaluate.grade(row["result"], row["labels"])
    summaries["Rule-based baseline"] = evaluate.summarise(rows)
    evaluate.save("baseline", rows, summaries["Rule-based baseline"], out_dir)

    if not a.baseline_only:
        from .agent import TriageAgent

        s = Settings()
        s = replace(s, model=a.model or s.model, think=not a.no_think)
        agent = TriageAgent(_backend(s), s)
        rows, spent = [], 0.0
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futures = {pool.submit(_agent_row, agent, iid): iid for iid in ids}
            for f in as_completed(futures):
                row = f.result()
                spent += row["result"]["cost_usd"]
                row["labels"] = load_incident(row["incident_id"])["labels"]
                row["grade"] = evaluate.grade(row["result"], row["labels"])
                g = row["grade"]
                print(f"{row['incident_id']}: {row['result']['status']:<16} verdict={'ok' if g['verdict_correct'] else 'WRONG':<5} "
                      f"tokens={row['result']['tokens']:>6} {row['result']['duration_s']:>5.0f}s", flush=True)
                rows.append(row)
        rows.sort(key=lambda r: r["incident_id"])
        name = f"{s.model}{'' if s.think else ' (no thinking)'}"
        summaries[name] = evaluate.summarise(rows)
        path = evaluate.save(s.model.replace(":", "-").replace("/", "_") + ("" if s.think else "-nothink"), rows, summaries[name], out_dir)
        print(f"\nsaved {path}")

    print("\n" + evaluate.markdown_table(summaries))
    return 0


def cmd_decide(a, approve: bool) -> int:
    act = actions.decide(a.run_id, a.action_id, approve=approve, approver=a.by, note=a.note or "")
    print(json.dumps(act, indent=2))
    return 0


def cmd_serve(a) -> int:
    import uvicorn

    uvicorn.run("triage_agent.web.app:app", host=a.host, port=a.port)
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="triage")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("investigate")
    s.add_argument("incident")
    s.set_defaults(fn=cmd_investigate)

    s = sub.add_parser("eval")
    s.add_argument("--incidents", nargs="*")
    s.add_argument("--baseline-only", action="store_true")
    s.add_argument("--model")
    s.add_argument("--no-think", action="store_true", help="disable the model's thinking mode (faster, usually less accurate)")
    s.add_argument("--workers", type=int, default=1, help="parallel investigations (a local GPU serves one at a time)")
    s.set_defaults(fn=cmd_eval)

    for name, approve in (("approve", True), ("reject", False)):
        s = sub.add_parser(name)
        s.add_argument("run_id")
        s.add_argument("action_id")
        s.add_argument("--by", required=True)
        s.add_argument("--note")
        s.set_defaults(fn=lambda a, approve=approve: cmd_decide(a, approve))

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
