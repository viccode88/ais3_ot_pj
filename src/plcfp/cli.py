from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from plcfp import __version__
from plcfp.passive import analyze_pcap
from plcfp.report import render_csv, render_json, render_sarif
from plcfp.scan import ScanOptions, scan_target
from plcfp.scheduler import ScanProfile
from plcfp.sigdb import SignatureError, load_signatures


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="plcfp",
        description="Independent OpenPLC v3/v4 evidence-based fingerprinting tool",
    )
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="actively fingerprint one explicitly named target")
    scan.add_argument("target")
    scan.add_argument(
        "--profile",
        choices=[profile.value for profile in ScanProfile],
        default=ScanProfile.STANDARD,
    )
    scan.add_argument("--max-layer", type=int, choices=(1, 2, 3, 4), default=4)
    scan.add_argument("--timeout", type=float)
    scan.add_argument("--interval", type=float)
    scan.add_argument("--packet-budget", type=int)
    scan.add_argument("--allow-public", action="store_true")
    scan.add_argument(
        "--dnp3-address",
        type=int,
        help="lab profile only; enables a DNP3 Link Status request to this outstation address",
    )
    scan.add_argument("--modbus-port", type=int, default=502)
    scan.add_argument("--v3-http-port", type=int, default=8080)
    scan.add_argument("--v4-https-port", type=int, default=8443)
    scan.add_argument("--enip-port", type=int, default=44818)
    scan.add_argument("--dnp3-port", type=int, default=20000)
    scan.add_argument("--opcua-port", type=int, default=4840)
    scan.add_argument("--signature-dir", type=Path)
    _output_arguments(scan)

    pcap = commands.add_parser("pcap", help="passively analyze a classic Ethernet PCAP")
    pcap.add_argument("capture", type=Path)
    pcap.add_argument("--target", help="only analyze packets to/from this IP")
    pcap.add_argument("--signature-dir", type=Path)
    _output_arguments(pcap)

    signatures = commands.add_parser("signatures", help="validate a signature database")
    signatures.add_argument("--signature-dir", type=Path)
    return root


def _output_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--format", choices=("json", "csv", "sarif"), default="json")
    command.add_argument("--output", type=Path)
    command.add_argument(
        "--no-raw",
        action="store_true",
        help="omit base64 raw responses from JSON output",
    )


def _render(report: object, output_format: str, no_raw: bool) -> str:
    if output_format == "csv":
        return render_csv(report)  # type: ignore[arg-type]
    if output_format == "sarif":
        return render_sarif(report)  # type: ignore[arg-type]
    return render_json(report, include_raw=not no_raw)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "signatures":
            database = load_signatures(args.signature_dir)
            print(json.dumps(database.metadata, ensure_ascii=False, indent=2))
            return 0
        if args.command == "scan":
            if args.dnp3_address is not None and args.profile != ScanProfile.LAB:
                raise ValueError("--dnp3-address requires --profile lab")
            report = scan_target(
                args.target,
                ScanOptions(
                    profile=ScanProfile(args.profile),
                    max_layer=args.max_layer,
                    interval=args.interval,
                    packet_budget=args.packet_budget,
                    timeout=args.timeout,
                    allow_public=args.allow_public,
                    dnp3_address=args.dnp3_address,
                    signature_dir=args.signature_dir,
                    modbus_port=args.modbus_port,
                    v3_http_port=args.v3_http_port,
                    v4_https_port=args.v4_https_port,
                    enip_port=args.enip_port,
                    dnp3_port=args.dnp3_port,
                    opcua_port=args.opcua_port,
                ),
            )
        else:
            if not args.capture.is_file():
                raise ValueError(f"capture does not exist: {args.capture}")
            report = analyze_pcap(
                args.capture,
                target=args.target,
                signature_dir=args.signature_dir,
            )
        rendered = _render(report, args.format, args.no_raw)
        if args.output:
            args.output.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""))
        else:
            print(rendered)
        return 0 if report.status not in {"CONFLICT", "BUDGET_EXCEEDED"} else 3
    except (ValueError, OSError, SignatureError) as exc:
        print(f"plcfp: {exc}", file=sys.stderr)
        return 2
