"""Thin, safe wrapper around external CLI tools.

Responsibilities:
  * locate a tool on PATH or in the Go bin dir (`go install` target)
  * run it with a timeout, capturing stdout/stderr
  * persist raw output + a command log per stage for auditability
  * never raise on a missing tool — return a result the stage can inspect
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

GO_BIN = Path.home() / "go" / "bin"


def _augmented_env() -> dict[str, str]:
    """Ensure child tools that shell out to other tools can find them."""
    env = dict(os.environ)
    extra = str(GO_BIN)
    if extra not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + os.pathsep + extra
    return env


def tool_path(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidate = GO_BIN / name
    return str(candidate) if candidate.exists() else None


def have(name: str) -> bool:
    return tool_path(name) is not None


@dataclass
class ToolResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    cmd: list[str]
    timed_out: bool = False
    missing: bool = False

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


def run(
    cmd: list[str],
    *,
    timeout: int | None = None,
    stdin_data: str | None = None,
    log_dir: Path | None = None,
    log_name: str | None = None,
    check_tool: bool = True,
) -> ToolResult:
    """Execute `cmd`, capturing output. `cmd[0]` is the tool name.

    Returns a ToolResult (with ``missing=True`` if the tool isn't installed)
    rather than raising, so a stage can degrade gracefully.
    """
    tool = cmd[0]
    resolved = tool_path(tool) if check_tool else tool
    if check_tool and resolved is None:
        return ToolResult(False, 127, "", f"{tool}: not found", 0.0, cmd, missing=True)
    if resolved:
        cmd = [resolved, *cmd[1:]]

    start = time.time()
    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_augmented_env(),
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = 124
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")) \
            + f"\n[timeout after {timeout}s]"
    except Exception as exc:  # noqa: BLE001 - surface any exec error to the stage
        rc, out, err = 1, "", f"{type(exc).__name__}: {exc}"

    duration = time.time() - start
    result = ToolResult(rc == 0 and not timed_out, rc, out, err, duration, cmd, timed_out)

    if log_dir is not None:
        _write_log(log_dir, log_name or tool, cmd, result)
    return result


def _write_log(log_dir: Path, name: str, cmd: list[str], result: ToolResult) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{name}.cmd").write_text(
        " ".join(cmd)
        + f"\n\n# rc={result.returncode} duration={result.duration_s:.1f}s "
        f"timed_out={result.timed_out}\n"
    )
    if result.stdout:
        (log_dir / f"{name}.stdout").write_text(result.stdout)
    if result.stderr:
        (log_dir / f"{name}.stderr").write_text(result.stderr)
