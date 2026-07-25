"""Non-exploitative vulnerability-behaviour regression API."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class RegressionResult:
    module_id: str
    observation: str
    evidence: list[str]


class RegressionModule(ABC):
    """Stable boundary for patch verification modules, separate from fuzzing."""

    module_id: str
    title: str
    references: list[str]

    @abstractmethod
    def preflight(self, context: object) -> bool: ...

    @abstractmethod
    def build_cases(self, context: object) -> list[bytes]: ...

    @abstractmethod
    def evaluate(self, results: list[object]) -> RegressionResult: ...
