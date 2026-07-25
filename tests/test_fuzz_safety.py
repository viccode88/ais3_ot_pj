import json
from pathlib import Path

import pytest

from modbus_cli.exceptions import SafetyPolicyError
from modbus_cli.fuzzing import STRATEGIES, CaseGenerator, save_cases
from modbus_cli.safety import SafetyPolicy


def test_seed_is_reproducible() -> None:
    first = CaseGenerator(123)
    second = CaseGenerator(123)
    assert [
        first.generate(i, strategy, 1, "127.0.0.1", 502).request_hex
        for i, strategy in enumerate(STRATEGIES)
    ] == [
        second.generate(i, strategy, 1, "127.0.0.1", 502).request_hex
        for i, strategy in enumerate(STRATEGIES)
    ]


def test_report_serialization(tmp_path: Path) -> None:
    case = CaseGenerator(1).generate(1, "boundary", 1, "127.0.0.1", 502)
    output = tmp_path / "report.json"
    save_cases(output, [case])
    assert json.loads(output.read_text())[0]["seed"] == 1


def test_safety_limits_and_public_target() -> None:
    policy = SafetyPolicy()
    assert policy.validate_target("127.0.0.1") == "127.0.0.1"
    with pytest.raises(SafetyPolicyError):
        policy.validate_target("8.8.8.8")
    with pytest.raises(SafetyPolicyError):
        policy.validate_fuzz(1, 51, 1)
