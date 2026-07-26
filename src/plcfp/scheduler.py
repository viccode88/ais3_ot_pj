from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

T = TypeVar("T")


class BudgetExceeded(RuntimeError):
    pass


class ScanProfile(str, Enum):
    SAFE = "safe"
    STANDARD = "standard"
    LAB = "lab"


@dataclass(frozen=True, slots=True)
class ProfileLimits:
    interval: float
    packet_budget: int
    timeout: float


PROFILE_LIMITS = {
    ScanProfile.SAFE: ProfileLimits(interval=0.5, packet_budget=60, timeout=10.0),
    ScanProfile.STANDARD: ProfileLimits(interval=0.2, packet_budget=300, timeout=10.0),
    ScanProfile.LAB: ProfileLimits(interval=0.05, packet_budget=1000, timeout=10.0),
}


class ProbeScheduler:
    """Single-target scheduler with a hard network-action budget."""

    def __init__(
        self,
        profile: ScanProfile,
        *,
        interval: float | None = None,
        packet_budget: int | None = None,
        timeout: float | None = None,
    ) -> None:
        defaults = PROFILE_LIMITS[profile]
        self.profile = profile
        self.interval = defaults.interval if interval is None else interval
        self.packet_budget = defaults.packet_budget if packet_budget is None else packet_budget
        self.timeout = defaults.timeout if timeout is None else timeout
        if self.interval < 0:
            raise ValueError("interval must be >= 0")
        if self.packet_budget < 1:
            raise ValueError("network-action budget must be >= 1")
        if self.timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.sent = 0
        self._last_action: float | None = None

    def run(self, action: Callable[[], T]) -> T:
        if self.sent >= self.packet_budget:
            raise BudgetExceeded(
                f"hard network-action budget exceeded ({self.sent}/{self.packet_budget})"
            )
        if self._last_action is not None:
            remaining = self.interval - (time.monotonic() - self._last_action)
            if remaining > 0:
                time.sleep(remaining)
        self.sent += 1
        self._last_action = time.monotonic()
        return action()
