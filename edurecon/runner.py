"""Subprocess execution wrapper: timeouts, output capture, logging, cancellation."""
from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass


@dataclass
class CmdResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    started: bool = True

    @property
    def ok(self) -> bool:
        return self.started and not self.timed_out


class ToolMissing(Exception):
    pass


def run(argv: list[str], *, timeout: int = 600, cwd: str | None = None,
        env: dict | None = None, log_path: str | None = None,
        input_text: str | None = None, cancel: threading.Event | None = None) -> CmdResult:
    """Run argv with a hard timeout. Streams combined output to log_path if given.

    cancel: an Event; if set mid-run the process is terminated and timed_out=False,
    returncode=-2 is returned.
    """
    start = time.time()
    full_env = dict(os.environ)
    if env:
        full_env.update(env)

    logf = open(log_path, "w", encoding="utf-8", errors="replace") if log_path else None
    if logf:
        logf.write(f"# $ {' '.join(shlex.quote(a) for a in argv)}\n\n")
        logf.flush()

    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=full_env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except FileNotFoundError as e:
        if logf:
            logf.close()
        raise ToolMissing(argv[0]) from e

    if input_text is not None and proc.stdin:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except Exception:
            pass

    out_lines: list[str] = []
    timed_out = False
    cancelled = False

    def reader():
        assert proc.stdout is not None
        for line in proc.stdout:
            out_lines.append(line)
            if logf:
                logf.write(line)
                logf.flush()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    deadline = start + timeout
    while proc.poll() is None:
        if time.time() > deadline:
            timed_out = True
            _kill(proc)
            break
        if cancel is not None and cancel.is_set():
            cancelled = True
            _kill(proc)
            break
        time.sleep(0.2)

    t.join(timeout=5)
    rc = proc.returncode if proc.returncode is not None else -1
    if cancelled:
        rc = -2
    if logf:
        logf.write(f"\n# exit={rc} timed_out={timed_out} duration={time.time()-start:.1f}s\n")
        logf.close()

    return CmdResult(
        argv=argv, returncode=rc, stdout="".join(out_lines), stderr="",
        duration=time.time() - start, timed_out=timed_out,
    )


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        pass
