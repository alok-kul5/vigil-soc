"""Settings (environment variables override the defaults)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    # The model runs locally through Ollama, so investigations are free and
    # no data leaves the machine. Any Ollama model with tool calling works.
    model: str = os.getenv("TRIAGE_MODEL", "qwen3:4b")
    ollama_url: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
    num_ctx: int = int(os.getenv("TRIAGE_NUM_CTX", "16384"))
    think: bool = os.getenv("TRIAGE_THINK", "1") == "1"
    temperature: float = float(os.getenv("TRIAGE_TEMPERATURE", "0.6"))
    seed: int = int(os.getenv("TRIAGE_SEED", "7"))

    # Per-run budget. The run is told to wrap up at 80% of either limit and
    # stopped at 100% (status "budget_exceeded").
    max_tokens_per_run: int = int(os.getenv("TRIAGE_MAX_TOKENS", "200000"))
    max_seconds_per_run: float = float(os.getenv("TRIAGE_MAX_SECONDS", "600"))
    max_turns: int = int(os.getenv("TRIAGE_MAX_TURNS", "25"))
    # Dollar cost per million tokens, for reporting and a dollar limit when the
    # backend is a paid endpoint. A local model costs nothing, hence 0.
    price_in_per_mtok: float = float(os.getenv("TRIAGE_PRICE_IN", "0"))
    price_out_per_mtok: float = float(os.getenv("TRIAGE_PRICE_OUT", "0"))
    max_cost_usd: float = float(os.getenv("TRIAGE_MAX_COST_USD", "0.50"))

    # Older tool results are compacted to a one-line summary (keeping their
    # evidence IDs) so long investigations fit in a small model's context.
    keep_full_tool_results: int = 6
    runs_dir: Path = field(default_factory=lambda: Path(os.getenv("TRIAGE_RUNS_DIR", ROOT / "runs")))
