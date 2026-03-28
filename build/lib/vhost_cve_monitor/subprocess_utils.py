from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

LOGGER = logging.getLogger(__name__)


@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def json_stdout(self) -> Optional[Union[Dict[Any, Any], List[Any]]]:
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError:
            return None


def command_exists(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_command(
    command: List[str],
    timeout: int,
    cwd: Optional[Union[str, Path]] = None,
) -> CommandResult:
    LOGGER.info("Starting command: %s (cwd=%s, timeout=%ss)", " ".join(command), cwd or ".", timeout)
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        LOGGER.warning("Command timed out: %s", command)
        return CommandResult(
            command=command,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    finally:
        LOGGER.debug("Command finished: %s", " ".join(command))
