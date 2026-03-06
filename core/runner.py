"""
core/runner.py — The Conductor.

Orchestrates skill discovery, scheduler setup, memory management,
and the main event loop.
"""
from __future__ import annotations

import logging
import signal
import time
from typing import Any, Optional

from rich.console import Console
from rich.table import Table

from core.config import Config
from core.memory import AgentMemory
from core.scheduler import AgentScheduler
from core.skill_loader import Skill, SkillLoader

logger = logging.getLogger(__name__)
console = Console()


class Runner:
    """
    The SecurityClaw Conductor.

    Lifecycle:
        1. Discover skills from /skills directory.
        2. Register each skill's `run` function with the scheduler.
        3. Build a context factory that injects shared services.
        4. Start the scheduler and enter a blocking loop.
        5. On SIGINT/SIGTERM, flush memory and shut down gracefully.
    """

    # Hard-coded fallback intervals (seconds) for known skills
    # On-demand (interactive) skills set to None — never auto-scheduled.
    DEFAULT_INTERVALS: dict[str, int] = {
        "anomaly_watcher": 60,          # 1-minute heartbeat
        "network_baseliner": 6 * 3600,  # 6-hour behavioral memory builder
        "fields_baseliner": 3600,       # 1-hour field-schema cataloguer
        "threat_analyst": 300,          # 5-minute analysis sweep
        # Interactive query skills — no scheduled interval
        "baseline_querier": None,
        "fields_querier": None,
        "opensearch_querier": None,
    }

    def __init__(
        self,
        db_connector: Any = None,
        llm_provider: Any = None,
        skills_dir=None,
        situation_path=None,
    ) -> None:
        self.cfg = Config()
        self.memory = AgentMemory(path=situation_path)
        self.scheduler = AgentScheduler()
        self.loader = SkillLoader(skills_dir=skills_dir)
        self.db = db_connector
        self.llm = llm_provider
        self._running = False
        self._skills: dict[str, Skill] = {}

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def setup(self) -> None:
        """Discover skills and wire up the scheduler."""
        self._skills = self.loader.discover()
        if not self._skills:
            logger.warning("No skills found — check your skills/ directory.")

        self.scheduler.set_context_factory(self._build_context)

        for name, skill in self._skills.items():
            interval = (
                skill.schedule_interval_seconds
                or self.DEFAULT_INTERVALS.get(name)
                or self.cfg.get("scheduler", "heartbeat_interval_seconds", default=60)
            )
            self.scheduler.register(
                name=name,
                fn=skill.run,
                interval_seconds=int(interval),
                run_immediately=False,
            )

        self._print_skill_table()

    def run(self) -> None:
        """Start the scheduler and block until signal received."""
        self._running = True
        self.scheduler.start()
        self.memory.set_status("ACTIVE")

        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)

        console.print("[bold green]SecurityClaw is running.[/] Press Ctrl+C to stop.")
        try:
            while self._running:
                time.sleep(1)
        finally:
            self._shutdown()

    def dispatch(self, skill_name: str, context: Optional[dict] = None) -> Any:
        """Manually fire a skill for testing or CLI invocation."""
        if skill_name not in self._skills:
            raise KeyError(f"Skill {skill_name!r} not loaded.")
        ctx = context or self._build_context()
        return self._skills[skill_name].run(ctx)

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _build_context(self) -> dict:
        """Construct the shared context injected into every skill run."""
        return {
            "db": self.db,
            "llm": self.llm,
            "memory": self.memory,
            "config": self.cfg,
            "skills": self._skills,
        }

    def _handle_shutdown(self, signum, frame) -> None:
        logger.info("Signal %d received — shutting down.", signum)
        self._running = False

    def _shutdown(self) -> None:
        console.print("[yellow]Shutting down SecurityClaw…[/]")
        self.scheduler.stop()
        self.memory.set_status("IDLE")
        self.memory.add_decision("Agent shut down cleanly.")
        console.print("[green]Done.[/]")

    def _print_skill_table(self) -> None:
        table = Table(title="Loaded Skills", show_lines=True)
        table.add_column("Skill", style="cyan")
        table.add_column("Interval (s)", style="magenta")
        table.add_column("Instruction Preview", style="white", max_width=60)
        for name, skill in self._skills.items():
            interval = str(
                skill.schedule_interval_seconds
                or self.DEFAULT_INTERVALS.get(name, "?")
            )
            preview = (skill.instruction[:80] + "…") if len(skill.instruction) > 80 else skill.instruction
            table.add_row(name, interval, preview.replace("\n", " "))
        console.print(table)
