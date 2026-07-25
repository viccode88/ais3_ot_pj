"""Argparse command adapter; protocol and transport layers contain no terminal I/O."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
import tomllib
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .exceptions import ModbusCLIError
from .fuzzing import (
    STRATEGIES,
    CaseGenerator,
    FuzzCase,
    FuzzProgressEvent,
    execute_cases,
    save_cases,
)
from .plugins import discover, validate
from .protocol import decode_adu, encode_adu
from .safety import SafetyPolicy
from .transport import TCPTransport

DEFAULT_CONFIG = Path.home() / ".config/modbus-cli/config.toml"


def _common_target(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target",
        required=True,
        metavar="HOST",
        help="authorized private/loopback IPv4 target or hostname",
    )
    parser.add_argument(
        "--port", type=int, default=502, metavar="PORT", help="TCP port (default: 502)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        metavar="SEC",
        help="connect/read timeout in seconds (default: 1.5)",
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="modbus-cli", description="Authorized Modbus laboratory testing framework"
    )
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True, metavar="COMMAND")
    commands.add_parser("version", help="show the version as JSON")
    commands.add_parser("info", help="show runtime, transport, strategy, and plugin information")
    build = commands.add_parser("build", help="build a Modbus TCP ADU without transmitting it")
    _packet_args(build)
    build.add_argument(
        "--output",
        choices=("text", "hex", "json", "binary"),
        default="text",
        help="output representation (default: text)",
    )
    decode = commands.add_parser("decode", help="decode a hex or binary Modbus TCP ADU")
    source = decode.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", metavar="HEX", help="hexadecimal ADU")
    source.add_argument("--file", type=Path, metavar="PATH", help="raw binary ADU file")
    decode.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="output representation (default: text)",
    )
    send = commands.add_parser("send", help="transmit an arbitrary Modbus TCP ADU")
    _common_target(send)
    source = send.add_mutually_exclusive_group(required=True)
    source.add_argument("--hex", metavar="HEX", help="hexadecimal ADU to transmit")
    source.add_argument("--file", type=Path, metavar="PATH", help="raw binary ADU file to transmit")
    send.add_argument(
        "--no-response",
        action="store_true",
        help="send without waiting for a response",
    )
    send.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="output representation (default: text)",
    )
    read = commands.add_parser("read", help="send one FC01-FC04 read request")
    read.add_argument(
        "kind",
        choices=("coils", "discrete-inputs", "holding-registers", "input-registers"),
        help="Modbus data type to read",
    )
    _common_target(read)
    read.add_argument("--unit-id", type=int, default=1, metavar="ID", help="unit ID (default: 1)")
    read.add_argument(
        "--address",
        type=int,
        required=True,
        metavar="ADDRESS",
        help="zero-based protocol address",
    )
    read.add_argument(
        "--quantity",
        type=int,
        required=True,
        metavar="COUNT",
        help="number of coils or registers",
    )
    write = commands.add_parser("write", help="preview a write request (writes are disabled)")
    write.add_argument(
        "kind",
        choices=("single-coil", "single-register", "multiple-coils", "multiple-registers"),
        help="Modbus write operation",
    )
    _common_target(write)
    write.add_argument("--unit-id", type=int, default=1, metavar="ID", help="unit ID (default: 1)")
    write.add_argument(
        "--address",
        type=int,
        required=True,
        metavar="ADDRESS",
        help="zero-based protocol address",
    )
    write.add_argument("--values", required=True, metavar="CSV", help="comma-separated integers")
    write.add_argument("--dry-run", action="store_true", help="only display the encoded request")
    write.add_argument(
        "--confirm",
        action="store_true",
        help="confirm transmission (still blocked by the default safety policy)",
    )
    fuzz = commands.add_parser(
        "fuzz", help="generate or explicitly execute deterministic fuzz cases"
    )
    _common_target(fuzz)
    fuzz.add_argument("--unit-id", type=int, default=1, metavar="ID", help="unit ID (default: 1)")
    fuzz.add_argument(
        "--strategy",
        action="append",
        choices=STRATEGIES,
        default=[],
        help="mutation strategy; repeat to cycle strategies (default: boundary)",
    )
    fuzz.add_argument(
        "--requests",
        type=int,
        default=100,
        metavar="COUNT",
        help="number of cases, 1..10000 (default: 100)",
    )
    pacing = fuzz.add_mutually_exclusive_group()
    pacing.add_argument(
        "--rate",
        type=float,
        default=10,
        metavar="RPS",
        help="maximum requests per second (default: 10)",
    )
    pacing.add_argument(
        "--interval",
        type=float,
        metavar="SEC",
        help="seconds to wait between requests instead of --rate",
    )
    fuzz.add_argument(
        "--concurrency",
        type=int,
        default=1,
        metavar="COUNT",
        help="safety limit; execution is currently sequential (default: 1)",
    )
    fuzz.add_argument("--seed", type=int, default=1, metavar="SEED", help="PRNG seed (default: 1)")
    fuzz.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/fuzz-report.json"),
        metavar="PATH",
        help="JSON report path (default: artifacts/fuzz-report.json)",
    )
    fuzz.add_argument(
        "--execute", action="store_true", help="required to transmit; otherwise generate only"
    )
    replay = commands.add_parser("replay", help="retransmit the first case in a JSON report")
    replay.add_argument("case", type=Path, metavar="CASE", help="case object or report array")
    replay.add_argument(
        "--times",
        type=int,
        default=1,
        metavar="COUNT",
        help="number of transmissions (default: 1)",
    )
    replay.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        metavar="SEC",
        help="connect/read timeout in seconds (default: 1.5)",
    )
    replay.add_argument(
        "--interval",
        type=float,
        default=0,
        metavar="SEC",
        help="seconds between replays (default: 0)",
    )
    minimize = commands.add_parser("minimize", help="create a structural baseline from a case")
    minimize.add_argument("case", type=Path, metavar="CASE", help="case object or report array")
    probe = commands.add_parser("probe", help="send one FC03 health probe")
    _common_target(probe)
    probe.add_argument("--unit-id", type=int, default=1, metavar="ID", help="unit ID (default: 1)")
    plugins = commands.add_parser("plugins", help="list, inspect, or validate installed plugins")
    plugins.add_argument(
        "action",
        choices=("list", "info", "validate"),
        help="plugin operation",
    )
    plugins.add_argument("name", nargs="?", help="plugin name for info or validate")
    config = commands.add_parser("config", help="initialize, show, or validate a TOML config file")
    config.add_argument(
        "action",
        choices=("show", "validate", "init"),
        help="configuration operation",
    )
    config.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_CONFIG,
        metavar="PATH",
        help=f"config path (default: {DEFAULT_CONFIG})",
    )
    return root


def _packet_args(item: argparse.ArgumentParser) -> None:
    item.add_argument(
        "--transaction-id",
        type=int,
        default=1,
        metavar="ID",
        help="MBAP transaction ID (default: 1)",
    )
    item.add_argument(
        "--protocol-id",
        type=int,
        default=0,
        metavar="ID",
        help="MBAP protocol ID (default: 0)",
    )
    item.add_argument("--unit-id", type=int, default=1, metavar="ID", help="unit ID (default: 1)")
    item.add_argument(
        "--function",
        type=int,
        required=True,
        metavar="CODE",
        help="decimal Modbus function code",
    )
    item.add_argument(
        "--address",
        type=int,
        default=0,
        metavar="ADDRESS",
        help="zero-based protocol address (default: 0)",
    )
    item.add_argument(
        "--quantity",
        type=int,
        default=1,
        metavar="COUNT",
        help="coil/register quantity (default: 1)",
    )
    item.add_argument(
        "--values", metavar="CSV", help="comma-separated decimal or 0x-prefixed values"
    )


def _packet(ns: argparse.Namespace) -> bytes:
    values = (
        [int(value, 0) for value in ns.values.split(",")] if getattr(ns, "values", None) else None
    )
    return encode_adu(
        ns.function,
        ns.address,
        ns.quantity,
        values,
        transaction_id=ns.transaction_id,
        protocol_id=ns.protocol_id,
        unit_id=ns.unit_id,
    )


def _validate_transport_options(ns: argparse.Namespace) -> None:
    if not 1 <= ns.port <= 65535 or ns.timeout <= 0:
        raise ValueError("invalid port or timeout")


def _safe_transport(ns: argparse.Namespace) -> TCPTransport:
    host = SafetyPolicy().validate_target(ns.target)
    _validate_transport_options(ns)
    return TCPTransport(host, ns.port, ns.timeout)


def _fuzz_request_type(case: FuzzCase) -> str:
    decoded = decode_adu(bytes.fromhex(case.request_hex))
    if decoded.function_code is None:
        return "malformed-request (function code unavailable)"
    details = [f"FC 0x{decoded.function_code:02X}"]
    if decoded.function_code & 0x80:
        details.append("exception-bit-set")
    if decoded.warnings:
        details.append("malformed framing")
    return f"{decoded.function_name or 'unknown'} ({', '.join(details)})"


def _fuzz_response_type(case: FuzzCase) -> str:
    if not case.response_hex:
        return "no-packet"
    decoded = decode_adu(bytes.fromhex(case.response_hex))
    if decoded.function_code is None:
        return "malformed-response (function code unavailable)"
    function = decoded.function_name or "unknown"
    details = [f"FC 0x{decoded.function_code:02X}"]
    if decoded.function_code & 0x80:
        exception = str(decoded.fields.get("exception_name", "unknown"))
        exception_code = (
            f"0x{decoded.exception_code:02X}"
            if decoded.exception_code is not None
            else "unavailable"
        )
        details.append(f"exception={exception} {exception_code}")
        if decoded.warnings:
            details.append("malformed framing")
        response_type = "exception-response"
    elif decoded.warnings:
        details.append("malformed framing")
        response_type = "malformed-response"
    else:
        response_type = "normal-response"
    return f"{response_type}/{function} ({', '.join(details)})"


def _print_fuzz_progress(event: FuzzProgressEvent, case: FuzzCase) -> None:
    if event == "sending":
        target = f"{case.target['host']}:{case.target['port']}"
        strategy = ",".join(case.strategy)
        print(
            f"[{case.case_id}] TX request-type={_fuzz_request_type(case)}; "
            f"target={target}; strategy={strategy}",
            file=sys.stderr,
            flush=True,
        )
        return
    elapsed = f"{case.elapsed_ms:.3f}" if case.elapsed_ms is not None else "unavailable"
    print(
        f"[{case.case_id}] RX response-type={_fuzz_response_type(case)}; "
        f"status={case.status}; elapsed_ms={elapsed}; classification={case.classification}",
        file=sys.stderr,
        flush=True,
    )


def run(ns: argparse.Namespace) -> Any:
    if ns.command == "version":
        return {"version": __version__}
    if ns.command == "info":
        return {
            "version": __version__,
            "python": platform.python_version(),
            "transports": ["tcp"],
            "fuzz_strategies": list(STRATEGIES),
            "plugins": [asdict(p) for p in discover()],
            "default_config": str(DEFAULT_CONFIG),
        }
    if ns.command == "build":
        packet = _packet(ns)
        if ns.output == "binary":
            sys.stdout.buffer.write(packet)
            return None
        if ns.output == "hex":
            return packet.hex().upper()
        return {
            "packet": decode_adu(packet).as_dict(),
            "hex": packet.hex().upper(),
            "packet_length": len(packet),
            "valid": True,
        }
    if ns.command == "decode":
        data = bytes.fromhex(ns.hex) if ns.hex else ns.file.read_bytes()
        return decode_adu(data).as_dict()
    if ns.command == "send":
        payload = bytes.fromhex(ns.hex) if ns.hex else ns.file.read_bytes()
        result = _safe_transport(ns).exchange(payload, expect_response=not ns.no_response)
        return {
            **asdict(result),
            "request_hex": payload.hex().upper(),
            "response_hex": result.response.hex().upper() if result.response else None,
            "decoded": decode_adu(result.response).as_dict() if result.response else None,
        }
    if ns.command == "read":
        function = ("coils", "discrete-inputs", "holding-registers", "input-registers").index(
            ns.kind
        ) + 1
        payload = encode_adu(function, ns.address, ns.quantity, unit_id=ns.unit_id)
        result = _safe_transport(ns).exchange(payload)
        return {
            **asdict(result),
            "decoded": decode_adu(result.response).as_dict() if result.response else None,
        }
    if ns.command == "write":
        values = [int(v, 0) for v in ns.values.split(",")]
        function = {
            "single-coil": 5,
            "single-register": 6,
            "multiple-coils": 15,
            "multiple-registers": 16,
        }[ns.kind]
        payload = encode_adu(function, ns.address, values=values, unit_id=ns.unit_id)
        preview = {
            "function": function,
            "address": ns.address,
            "values": values,
            "request_hex": payload.hex().upper(),
        }
        if ns.dry_run:
            return {"dry_run": True, **preview}
        if not ns.confirm:
            raise ValueError("writes require --confirm (or use --dry-run)")
        if not SafetyPolicy().allow_write_functions:
            raise ValueError("writes are disabled by the default safety policy")
    if ns.command == "fuzz":
        policy = SafetyPolicy()
        host = policy.validate_target(ns.target)
        _validate_transport_options(ns)
        if ns.interval is not None and ns.interval <= 0:
            raise ValueError("interval must be > 0")
        rate = 1 / ns.interval if ns.interval is not None else ns.rate
        policy.validate_fuzz(ns.requests, rate, ns.concurrency)
        strategies = ns.strategy or ["boundary"]
        generator = CaseGenerator(ns.seed)
        cases = [
            generator.generate(i + 1, strategies[i % len(strategies)], ns.unit_id, host, ns.port)
            for i in range(ns.requests)
        ]
        interval = ns.interval if ns.interval is not None else 1 / rate
        execute_cases(cases, ns.timeout, interval, _print_fuzz_progress) if ns.execute else None
        save_cases(ns.output, cases)
        return {
            "seed": ns.seed,
            "cases": len(cases),
            "executed": ns.execute,
            "interval": interval,
            "report": str(ns.output),
        }
    if ns.command == "replay":
        if ns.interval < 0:
            raise ValueError("interval must be >= 0")
        raw = json.loads(ns.case.read_text())
        case = raw[0] if isinstance(raw, list) else raw
        host = SafetyPolicy().validate_target(case["target"]["host"])
        results = []
        for index in range(ns.times):
            results.append(
                asdict(
                    TCPTransport(host, int(case["target"]["port"]), ns.timeout).exchange(
                        bytes.fromhex(case["request_hex"])
                    )
                )
            )
            if ns.interval and index < ns.times - 1:
                time.sleep(ns.interval)
        return {
            "case_id": case["case_id"],
            "results": results,
            "stable": len({r["status"] for r in results}) == 1,
        }
    if ns.command == "minimize":
        raw = json.loads(ns.case.read_text())
        case = raw[0] if isinstance(raw, list) else raw
        case["request_hex"] = case["request_hex"][:24]
        case["mutations"] = case.get("mutations", [])[:1]
        output = ns.case.with_name(ns.case.stem + "-minimized.json")
        output.write_text(json.dumps(case, indent=2))
        return {
            "output": str(output),
            "note": "structural baseline minimization; replay verification is required",
        }
    if ns.command == "probe":
        payload = encode_adu(3, 0, 1, unit_id=ns.unit_id)
        result = _safe_transport(ns).exchange(payload)
        return {
            "tcp": "confirmed" if result.status == "response" else result.status,
            "modbus": "likely"
            if result.response and not decode_adu(result.response).warnings
            else "inconclusive",
            "elapsed_ms": result.elapsed_ms,
        }
    if ns.command == "plugins":
        if ns.action == "list":
            return [asdict(item) for item in discover()]
        if not ns.name:
            raise ValueError("plugin name is required")
        return {"name": ns.name, "validation": validate(ns.name)}
    if ns.command == "config":
        return _config(ns)
    raise ValueError("unsupported command")


def _config(ns: argparse.Namespace) -> Any:
    if ns.action == "init":
        ns.file.parent.mkdir(parents=True, exist_ok=True)
        ns.file.write_text(
            "[safety]\nallow_public_targets = false\nallow_write_functions = false\nmax_rate = 50\n"
        )
        return {"created": str(ns.file)}
    data = tomllib.loads(ns.file.read_text())
    if ns.action == "validate" and not isinstance(data.get("safety", {}), dict):
        raise ValueError("[safety] must be a table")
    return data if ns.action == "show" else {"valid": True, "file": str(ns.file)}


def main(argv: list[str] | None = None) -> int:
    try:
        ns = parser().parse_args(argv)
        output = run(ns)
        if output is not None:
            print(
                output
                if isinstance(output, str)
                else json.dumps(output, indent=2, default=lambda value: None)
            )
        return 0
    except (
        ModbusCLIError,
        ValueError,
        OSError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        LookupError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
