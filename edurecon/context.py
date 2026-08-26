"""Per-target execution context handed to every stage function."""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Callable

from .config import Config
from .models import Finding, TargetState
from .runner import CmdResult, run
from .scope import ScopeGuard


@dataclass
class StageCtx:
    ts: TargetState
    cfg: Config
    run_dir: str
    tdir: str                         # per-target artifact directory (abs)
    scope: ScopeGuard
    cancel: threading.Event
    on_update: Callable[[], None] = lambda: None
    logger: Callable[[str], None] = lambda m: None

    def __post_init__(self) -> None:
        os.makedirs(self.tdir, exist_ok=True)

    # -- filesystem helpers ------------------------------------------------
    def artifact(self, name: str) -> str:
        return os.path.join(self.tdir, name)

    def rel(self, abs_path: str) -> str:
        try:
            return os.path.relpath(abs_path, self.run_dir).replace("\\", "/")
        except ValueError:
            return abs_path

    # -- command execution -------------------------------------------------
    def run(self, argv: list[str], *, stage: str, log_name: str,
            timeout: int | None = None, input_text: str | None = None) -> CmdResult:
        log_path = self.artifact(log_name)
        to = timeout if timeout is not None else self.cfg.timeouts.get(stage, 900)
        self.logger(f"[{self.ts.host}] {stage}: $ {' '.join(argv)}")
        res = run(argv, timeout=to, log_path=log_path, input_text=input_text,
                  cancel=self.cancel)
        self.ts.stage(stage).artifacts.append(self.rel(log_path))
        return res

    def record_artifact(self, stage: str, abs_path: str) -> None:
        if os.path.exists(abs_path):
            rp = self.rel(abs_path)
            arts = self.ts.stage(stage).artifacts
            if rp not in arts:
                arts.append(rp)

    # -- findings ----------------------------------------------------------
    def finding(self, *, stage: str, category: str, title: str,
                severity: str = "info", confidence: str = "medium",
                evidence: dict | None = None, artifacts: list[str] | None = None,
                dedup_key: str = "") -> Finding:
        f = Finding(
            target=self.ts.host, stage=stage, category=category, title=title,
            severity=severity, confidence=confidence, evidence=evidence or {},
            artifacts=artifacts or [], dedup_key=dedup_key,
        )
        self.ts.findings.append(f)
        self.logger(f"[{self.ts.host}] FINDING [{severity}] {title}")
        return f

    def aborted(self) -> bool:
        return self.cancel.is_set()
