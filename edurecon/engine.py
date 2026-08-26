"""Execution engine: expand targets, run the per-target pipeline concurrently, triage."""
from __future__ import annotations

import copy
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config, ALL_STAGES, INTENSITY_STAGES
from .context import StageCtx
from .models import TargetState, make_id
from .scope import ParsedTarget, ScopeGuard, ScopeError, parse_target
from .store import Run, RunStore
from . import stages, triage

_DISPATCH = {
    "portscan":  lambda c, co: stages.stage_portscan(c),
    "webdisco":  lambda c, co: stages.stage_webdisco(c),
    "exposures": lambda c, co: stages.stage_exposures(c),
    "secrets":   lambda c, co: stages.stage_secrets(c),
    "phpcgi":    lambda c, co: stages.stage_phpcgi(c),
    "xss":       lambda c, co: stages.stage_xss(c),
    "sqli":      lambda c, co: stages.stage_sqli(c, co),
    "cred":      lambda c, co: stages.stage_cred(c, co),
    "wp":        lambda c, co: stages.stage_wp(c),
}


class Engine:
    def __init__(self, cfg: Config, store: RunStore) -> None:
        self.cfg = cfg
        self.store = store
        self._cancels: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------
    def start_run(self, raw_targets: list[str], options: dict | None = None,
                  block: bool = False) -> Run:
        options = options or {}
        run = self.store.create({"intensity": options.get("intensity", self.cfg.intensity),
                                 "concurrency": options.get("concurrency", self.cfg.concurrency),
                                 "targets": raw_targets})
        cancel = threading.Event()
        with self._lock:
            self._cancels[run.id] = cancel
        t = threading.Thread(target=self._safe_execute,
                             args=(run, raw_targets, options, cancel), daemon=True)
        with self._lock:
            self._threads[run.id] = t
        t.start()
        if block:
            t.join()
        return run

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            ev = self._cancels.get(run_id)
        if ev:
            ev.set()
            return True
        return False

    def is_running(self, run_id: str) -> bool:
        with self._lock:
            t = self._threads.get(run_id)
        return bool(t and t.is_alive())

    # -- execution ---------------------------------------------------------
    def _safe_execute(self, run, raw_targets, options, cancel):
        try:
            self._execute(run, raw_targets, options, cancel)
        except Exception as e:
            run.status = "error"
            run.error = f"{type(e).__name__}: {e}"
            self.store.log(run, f"FATAL: {traceback.format_exc(limit=4)}")
            self.store.save(run)

    def _run_cfg(self, options: dict) -> Config:
        cfg = copy.deepcopy(self.cfg)
        if options.get("intensity") in INTENSITY_STAGES:
            cfg.intensity = options["intensity"]
        if options.get("concurrency"):
            cfg.concurrency = int(options["concurrency"])
        return cfg

    def _execute(self, run: Run, raw_targets: list[str], options: dict,
                 cancel: threading.Event) -> None:
        cfg = self._run_cfg(options)
        run_dir = self.store.run_dir(run.id)
        log = lambda m: self.store.log(run, m)

        run.status = "expanding"
        self.store.save(run)

        parsed: list[ParsedTarget] = []
        for line in raw_targets:
            try:
                parsed.append(parse_target(line))
            except ScopeError as e:
                log(f"skip target {line!r}: {e}")

        guard = ScopeGuard(cfg.extra_allowed_cidrs,
                           allow_subdomains=cfg.subdomain_allow_scope)
        for pt in parsed:
            guard.add(pt)

        concrete = self._expand(parsed, cfg, run_dir, guard, cancel, log)
        run.targets = [self._mk_state(p) for p in concrete]
        log(f"expanded to {len(run.targets)} concrete target(s)")
        self.store.save(run)

        if cancel.is_set():
            run.status = "cancelled"
            self.store.save(run)
            return

        run.status = "running"
        self.store.save(run)

        workers = max(1, cfg.concurrency)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self._run_pipeline, ts, cfg, run, guard, cancel)
                    for ts in run.targets]
            for _ in as_completed(futs):
                pass

        run.status = "cancelled" if cancel.is_set() else "done"
        self.store.save(run)
        log(f"run {run.status}")

    def _expand(self, parsed, cfg, run_dir, guard, cancel, log) -> list[ParsedTarget]:
        concrete: list[ParsedTarget] = []
        for pt in parsed:
            if cancel.is_set():
                break
            if pt.kind == "cidr":
                if cfg.hostdiscovery_enabled:
                    for ip in stages.host_discovery(pt, cfg, run_dir, log):
                        guard.add_host(ip)
                        concrete.append(ParsedTarget(raw=ip, kind="host", host=ip))
                continue
            concrete.append(pt)
            if cfg.subdomain_enabled and not stages._is_ip(pt.host):
                for sub in stages.subdomain_enum(pt.host, cfg, run_dir, log):
                    guard.add_host(sub)
                    if sub != pt.host:
                        concrete.append(ParsedTarget(
                            raw=sub, kind="host", host=sub,
                            scheme=(pt.scheme if pt.kind == "url" else "http")))
        # dedupe
        uniq: dict[tuple, ParsedTarget] = {}
        for p in concrete:
            uniq.setdefault((p.host, p.scheme, p.port, p.base_url), p)
        return list(uniq.values())

    def _mk_state(self, p: ParsedTarget) -> TargetState:
        return TargetState(raw=p.raw, host=p.host, scheme=p.scheme,
                           port_hint=p.port, base_url=p.base_url)

    def _run_pipeline(self, ts: TargetState, cfg: Config, run: Run,
                      guard: ScopeGuard, cancel: threading.Event) -> None:
        run_dir = self.store.run_dir(run.id)
        tdir = os.path.join(run_dir, "targets", _slug(ts))
        logger = lambda m: self.store.log(run, m)
        on_update = lambda: self.store.save(run)
        try:
            ts.status = "running"
            for name in ALL_STAGES:
                ts.stage(name)                       # ensure pending record exists
            ctx = StageCtx(ts=ts, cfg=cfg, run_dir=run_dir, tdir=tdir, scope=guard,
                           cancel=cancel, on_update=on_update, logger=logger)
            on_update()
            for name in ALL_STAGES:
                if cancel.is_set():
                    break
                execute = cfg.stage_runs(name)
                candidate = cfg.stage_runs(name + "_candidate")
                st = ts.stage(name)
                if not execute and not candidate:
                    st.status = "skipped"
                    continue
                st.status = "running"
                st.started = time.time()
                on_update()
                try:
                    _DISPATCH[name](ctx, candidate and not execute)
                    st.status = "done"
                except ScopeError as e:
                    st.status = "error"
                    st.error = str(e)
                except Exception as e:
                    st.status = "error"
                    st.error = f"{type(e).__name__}: {e}"
                    logger(f"[{ts.host}] {name} ERROR: {traceback.format_exc(limit=3)}")
                st.ended = time.time()
                on_update()
            try:
                triage.triage_target(ts, cfg)
            except Exception as e:
                logger(f"[{ts.host}] triage ERROR: {e}")
            ts.status = "cancelled" if cancel.is_set() else "done"
            on_update()
        except Exception as e:
            ts.status = "error"
            ts.error = f"{type(e).__name__}: {e}"
            logger(f"[{ts.host}] PIPELINE FATAL: {traceback.format_exc(limit=3)}")
            self.store.save(run)


def _slug(ts: TargetState) -> str:
    base = ts.host.replace(":", "_").replace("/", "_")
    if ts.port_hint:
        base += f"-{ts.port_hint}"
    return f"{base}-{make_id(ts.raw, ts.scheme, str(ts.port_hint))}"
