from __future__ import annotations

import hashlib
import os
import ssl
import tempfile
import time
from datetime import UTC, datetime
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget, socket_address
from plcfp.scheduler import ProbeScheduler


def _name_dict(name: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in name:
        for key, value in rdn:
            result[key] = value
    return result


def _decode_der_certificate(der: bytes) -> dict[str, Any]:
    pem = ssl.DER_cert_to_PEM_cert(der)
    path = ""
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
            handle.write(pem)
            path = handle.name
        # CPython's decoder is used so the installed tool has no cryptography dependency.
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        return dict(decoded)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass


def probe_tls(
    target: ResolvedTarget, scheduler: ProbeScheduler, port: int = 8443
) -> list[Observation]:
    started = time.monotonic()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    def handshake() -> tuple[bytes, str | None, tuple[str, str, int] | None]:
        with __import__("socket").socket(target.family, __import__("socket").SOCK_STREAM) as raw:
            raw.settimeout(scheduler.timeout)
            raw.connect(socket_address(target, port))
            with context.wrap_socket(raw, server_hostname=target.original) as tls_sock:
                certificate = tls_sock.getpeercert(binary_form=True)
                if certificate is None:
                    raise ssl.SSLError("server did not provide a certificate")
                return (
                    certificate,
                    tls_sock.version(),
                    tls_sock.cipher(),
                )

    try:
        der, protocol, cipher = scheduler.run(handshake)
        latency = round((time.monotonic() - started) * 1000, 3)
        decoded = _decode_der_certificate(der)
        subject = _name_dict(decoded.get("subject", ()))
        issuer = _name_dict(decoded.get("issuer", ()))
        not_before = decoded.get("notBefore")
        not_after = decoded.get("notAfter")
        validity_days: int | None = None
        if isinstance(not_before, str) and isinstance(not_after, str):
            validity_days = round(
                (ssl.cert_time_to_seconds(not_after) - ssl.cert_time_to_seconds(not_before)) / 86400
            )
        value = {
            "subject": subject,
            "issuer": issuer,
            "serial_number": decoded.get("serialNumber"),
            "not_before": not_before,
            "not_after": not_after,
            "validity_days": validity_days,
            "subject_alt_names": decoded.get("subjectAltName", ()),
            "sha256": hashlib.sha256(der).hexdigest(),
            "tls_version": protocol,
            "cipher": cipher[0] if cipher else None,
            "captured_at": datetime.now(UTC).isoformat(),
        }
        observations = [
            Observation(
                probe_id="tls.8443.certificate",
                feature="tls.cert",
                value=value,
                latency_ms=latency,
                raw=der,
            ),
            Observation(
                probe_id="tls.8443.subject_cn",
                feature="tls.cert.subject_cn",
                value=subject.get("commonName"),
                latency_ms=latency,
            ),
            Observation(
                probe_id="tls.8443.validity",
                feature="tls.cert.validity_days",
                value=validity_days,
                latency_ms=latency,
            ),
            Observation(
                probe_id="tls.8443.stack",
                feature="tls.stack",
                value={"protocol": protocol, "cipher": cipher[0] if cipher else None},
                latency_ms=latency,
            ),
        ]
        return observations
    except (OSError, ssl.SSLError, ValueError) as exc:
        return [
            Observation(
                probe_id="tls.8443.certificate",
                feature="tls.cert",
                state=ProbeState.UNAVAILABLE,
                latency_ms=round((time.monotonic() - started) * 1000, 3),
                error=str(exc),
            )
        ]
