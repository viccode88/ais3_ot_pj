import json
from pathlib import Path

from modbus_cli.cli import main


def test_build_json(capsys: object) -> None:
    assert (
        main(["build", "--function", "3", "--address", "0", "--quantity", "10", "--output", "json"])
        == 0
    )
    output = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert output["hex"] == "00010000000601030000000A"


def test_decode_invalid_hex(capsys: object) -> None:
    assert main(["decode", "--hex", "zz"]) == 2
    assert "error:" in capsys.readouterr().err  # type: ignore[attr-defined]


def test_write_dry_run(capsys: object) -> None:
    code = main(
        [
            "write",
            "single-register",
            "--target",
            "127.0.0.1",
            "--address",
            "1",
            "--values",
            "12",
            "--dry-run",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True  # type: ignore[attr-defined]


def test_offline_fuzz(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "cases.json"
    assert main(["fuzz", "--target", "127.0.0.1", "--requests", "2", "--output", str(output)]) == 0
    assert len(json.loads(output.read_text())) == 2
    assert json.loads(capsys.readouterr().out)["executed"] is False  # type: ignore[attr-defined]


def test_fuzz_interval_is_reported(tmp_path: Path, capsys: object) -> None:
    output = tmp_path / "cases.json"
    assert (
        main(
            [
                "fuzz",
                "--target",
                "127.0.0.1",
                "--requests",
                "1",
                "--interval",
                "0.5",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["interval"] == 0.5  # type: ignore[attr-defined]


def test_fuzz_rejects_non_positive_interval(capsys: object) -> None:
    assert main(["fuzz", "--target", "127.0.0.1", "--interval", "0"]) == 2
    assert "interval must be > 0" in capsys.readouterr().err  # type: ignore[attr-defined]
