"""Kill-switch. Single source of truth for halting all activity."""
from __future__ import annotations

import os
from pathlib import Path


class KillSwitch:
    """Checks both filesystem flag and env var. Either triggers halt."""

    ENV_VAR = "APT_SIM_STOP"

    def __init__(self, flag_file: str | Path) -> None:
        self.flag_file = Path(flag_file)

    def is_active(self) -> bool:
        if os.environ.get(self.ENV_VAR) == "1":
            return True
        return self.flag_file.exists()

    def reason(self) -> str | None:
        if os.environ.get(self.ENV_VAR) == "1":
            return f"env var {self.ENV_VAR}=1"
        if self.flag_file.exists():
            return f"flag file present: {self.flag_file}"
        return None

    def engage(self, reason: str = "manual") -> None:
        self.flag_file.parent.mkdir(parents=True, exist_ok=True)
        self.flag_file.write_text(reason, encoding="utf-8")

    def disengage(self) -> None:
        if self.flag_file.exists():
            self.flag_file.unlink()
