"""Run state: in-memory + JSON persistence under workdir/<run_id>/run.json."""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from .models import TargetState, SEVERITY_ORDER


@dataclass
class Run:
    id: str
    created: str
    options: dict
    status: str = "pending"          # pending|expanding|running|done|cancelled|error
    error: str = ""
    targets: list[TargetState] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for t in self.targets:
            for k, v in t.finding_counts().items():
                counts[k] += v
        return {
            "targets": len(self.targets),
            "done": sum(1 for t in self.targets if t.status == "done"),
            "severity": counts,
            "findings": sum(counts.values()),
        }

    def to_dict(self, include_targets: bool = True) -> dict:
        d = {
            "id": self.id, "created": self.created, "status": self.status,
            "options": self.options, "error": self.error,
            "summary": self.summary(),
            "logs": self.logs[-400:],
        }
        if include_targets:
            d["targets"] = [t.to_dict() for t in self.targets]
        return d


class RunStore:
    def __init__(self, workdir: str) -> None:
        self.workdir = workdir
        self.lock = threading.RLock()
        self.runs: dict[str, Run] = {}
        os.makedirs(workdir, exist_ok=True)

    def run_dir(self, run_id: str) -> str:
        d = os.path.join(self.workdir, run_id)
        os.makedirs(d, exist_ok=True)
        return d

    def new_id(self) -> str:
        return "run-" + datetime.now().strftime("%Y%m%d-%H%M%S")

    def create(self, options: dict) -> Run:
        with self.lock:
            rid = self.new_id()
            # collision guard within the same second
            if rid in self.runs:
                rid += "-" + str(len(self.runs))
            run = Run(id=rid, created=datetime.now().isoformat(timespec="seconds"),
                      options=options)
            self.runs[rid] = run
            self.run_dir(rid)
            return run

    def get(self, run_id: str) -> Run | None:
        with self.lock:
            return self.runs.get(run_id)

    def list(self) -> list[Run]:
        with self.lock:
            return sorted(self.runs.values(), key=lambda r: r.created, reverse=True)

    def log(self, run: Run, msg: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        with self.lock:
            run.logs.append(f"{stamp} {msg}")

    def save(self, run: Run) -> None:
        run_dir = self.run_dir(run.id)
        path = os.path.join(run_dir, "run.json")
        # Serialize the whole write+replace: concurrent target pipelines all call
        # save() for the same run, and on Windows a shared tmp name + racing
        # os.replace() raises PermissionError [WinError 32], FATAL-ing a target.
        # Unique tmp per writer + lock + retry makes it atomic and safe.
        tmp = os.path.join(run_dir, f".run.{os.getpid()}.{threading.get_ident()}.tmp")
        with self.lock:
            data = run.to_dict()
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            for _ in range(6):
                try:
                    os.replace(tmp, path)
                    return
                except PermissionError:
                    time.sleep(0.05)   # a reader briefly holds run.json; retry
            try:
                os.remove(tmp)
            except OSError:
                pass

    def load_existing(self) -> None:
        """Reload prior runs (status only; targets stay as saved dicts view)."""
        if not os.path.isdir(self.workdir):
            return
        for name in os.listdir(self.workdir):
            rj = os.path.join(self.workdir, name, "run.json")
            if not os.path.exists(rj):
                continue
            try:
                with open(rj, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            with self.lock:
                if data.get("id") and data["id"] not in self.runs:
                    # lightweight shell; full targets remain readable from disk via API
                    run = Run(id=data["id"], created=data.get("created", ""),
                              options=data.get("options", {}),
                              status=data.get("status", "done"),
                              logs=data.get("logs", []))
                    run._raw = data  # type: ignore  # cached dict for read-only API
                    self.runs[data["id"]] = run
