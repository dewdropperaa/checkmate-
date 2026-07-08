"""Real-process timeout/kill enforcement tests."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

from tools.base import run_subprocess_safely


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@pytest.mark.asyncio
async def test_timeout_kills_parent_and_spawned_child_process(tmp_path: Path) -> None:
    """A real hanging process tree should be terminated on timeout."""
    child_pid_file = tmp_path / "child_pid.txt"

    script = (
        "import subprocess, sys, time, pathlib;"
        f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
        f"pathlib.Path(r'{child_pid_file.as_posix()}').write_text(str(child.pid), encoding='utf-8');"
        "time.sleep(60)"
    )

    exit_code, _stdout, _stderr, timed_out = await run_subprocess_safely(
        binary_path=Path(sys.executable),
        args=["-c", script],
        timeout=1.0,
    )

    assert timed_out is True
    assert exit_code == -1
    assert child_pid_file.exists()

    child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
    await asyncio.sleep(0.5)
    assert _process_exists(child_pid) is False
