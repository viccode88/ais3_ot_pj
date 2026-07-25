from typing import ClassVar

from modbus_cli.regression import RegressionModule, RegressionResult


class ExampleRegression(RegressionModule):
    module_id = "CVE-YYYY-NNNN"
    title = "Template: observed behavior only"
    references: ClassVar[list[str]] = []

    def preflight(self, context: object) -> bool:
        return False  # Fail closed until a lab-specific preflight is implemented.

    def build_cases(self, context: object) -> list[bytes]:
        return []

    def evaluate(self, results: list[object]) -> RegressionResult:
        return RegressionResult(self.module_id, "not-run", [])
