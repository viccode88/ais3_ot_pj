from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import struct
import time
from dataclasses import dataclass
from typing import Any

from plcfp.model import Observation, ProbeState
from plcfp.net import ResolvedTarget
from plcfp.scheduler import BudgetExceeded, ProbeScheduler

V3_ROUTES = (
    "/hardware",
    "/settings",
    "/users",
    "/programs",
    "/modbus",
    "/monitoring",
    "/reload-program",
    "/upload-program",
    "/restore_custom_hardware",
    "/add-modbus-device",
    "/delete-device",
    "/modbus-edit-device",
)


@dataclass(slots=True)
class HTTPResult:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    latency_ms: float

    @property
    def header_map(self) -> dict[str, str]:
        return {key.lower(): value for key, value in self.headers}

    @property
    def raw(self) -> bytes:
        status = f"HTTP/1.1 {self.status} {self.reason}\r\n".encode()
        headers = b"".join(f"{key}: {value}\r\n".encode() for key, value in self.headers)
        return status + headers + b"\r\n" + self.body


def _request(
    target: ResolvedTarget,
    scheduler: ProbeScheduler,
    *,
    port: int,
    tls: bool,
    method: str,
    path: str,
    body: bytes | None = None,
) -> HTTPResult:
    def action() -> HTTPResult:
        started = time.monotonic()
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                target.address, port, timeout=scheduler.timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(target.address, port, timeout=scheduler.timeout)
        try:
            headers = {
                "Host": target.original,
                "User-Agent": "plcfp/0.1",
                "Accept": "*/*",
                "Connection": "close",
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(len(body))
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(1024 * 1024)
            return HTTPResult(
                response.status,
                response.reason,
                response.getheaders(),
                response_body,
                round((time.monotonic() - started) * 1000, 3),
            )
        finally:
            connection.close()

    return scheduler.run(action)


def _error_observation(probe_id: str, feature: str, exc: Exception) -> Observation:
    return Observation(
        probe_id=probe_id,
        feature=feature,
        state=ProbeState.UNAVAILABLE,
        error=str(exc),
    )


def _response_value(result: HTTPResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "reason": result.reason,
        "headers": result.headers,
        "header_order": [key for key, _ in result.headers],
        "server": result.header_map.get("server"),
        "content_type": result.header_map.get("content-type"),
        "location": result.header_map.get("location"),
        "body_length": len(result.body),
        "body_sha256": hashlib.sha256(result.body).hexdigest(),
    }


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~3
    for offset in range(0, rounded, 4):
        k1 = struct.unpack_from("<I", data, offset)[0]
        k1 = (k1 * 0xCC9E2D51) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * 0x1B873593) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    for index, byte in enumerate(tail):
        k1 ^= byte << (8 * index)
    if tail:
        k1 = (k1 * 0xCC9E2D51) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * 0x1B873593) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


def probe_v4_https(
    target: ResolvedTarget, scheduler: ProbeScheduler, port: int = 8443
) -> list[Observation]:
    requests = (
        ("GET", "/", None, "root"),
        ("GET", "/api/get-users-info", None, "users_info"),
        ("POST", "/api/login", b"", "login_empty"),
        ("GET", "/api/status", None, "status"),
        (
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            None,
            "socketio_handshake",
        ),
    )
    observations: list[Observation] = []
    for method, path, body, name in requests:
        feature = f"http.v4.{name}"
        try:
            result = _request(
                target,
                scheduler,
                port=port,
                tls=True,
                method=method,
                path=path,
                body=body,
            )
            value = _response_value(result)
            if name == "users_info":
                try:
                    parsed = json.loads(result.body)
                    value["json"] = parsed
                    if isinstance(parsed, dict):
                        value["json_fields"] = sorted(parsed)
                    elif isinstance(parsed, list):
                        value["json_fields"] = sorted(
                            {key for item in parsed if isinstance(item, dict) for key in item}
                        )
                    value["setup_incomplete"] = parsed == [] or parsed == {}
                except (UnicodeDecodeError, json.JSONDecodeError):
                    value["json_error"] = True
            elif name in {"login_empty", "status"}:
                try:
                    parsed = json.loads(result.body)
                    value["json"] = parsed
                    value["json_fields"] = sorted(parsed) if isinstance(parsed, dict) else []
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            elif name == "socketio_handshake":
                payload = result.body
                if payload.startswith(b"0"):
                    try:
                        engine = json.loads(payload[1:])
                        value["engine_io"] = engine
                        value["has_max_payload"] = "maxPayload" in engine
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass
            observations.append(
                Observation(
                    probe_id=f"http.v4.{name}",
                    feature=feature,
                    value=value,
                    latency_ms=result.latency_ms,
                    raw=result.raw,
                )
            )
        except BudgetExceeded:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            observations.append(_error_observation(f"http.v4.{name}", feature, exc))
    return observations


def probe_v3_http(
    target: ResolvedTarget, scheduler: ProbeScheduler, port: int = 8080
) -> list[Observation]:
    observations: list[Observation] = []
    for path, name in (
        ("/", "root"),
        ("/login", "login"),
        ("/static/style.css", "style"),
        ("/favicon.ico", "favicon"),
        ("/static/logo-openplc.png", "logo"),
        ("/static/fonts/roboto/roboto.css", "roboto_css"),
    ):
        feature = f"http.v3.{name}"
        try:
            result = _request(target, scheduler, port=port, tls=False, method="GET", path=path)
            value = _response_value(result)
            if name == "login":
                lowered = result.body.lower()
                value["has_password_field"] = b'type="password"' in lowered
                if not value["has_password_field"]:
                    value["has_password_field"] = b"type='password'" in lowered
                value["mentions_openplc"] = b"openplc" in lowered
                release = re.search(rb"Release:\s*(\d{4}-\d{2}-\d{2})", result.body)
                if release:
                    value["release_date"] = release.group(1).decode("ascii")
            if name in {"style", "logo", "roboto_css"}:
                value["last_modified"] = result.header_map.get("last-modified")
            if name == "favicon":
                value["mmh3_32"] = _murmur3_32(result.body)
            observations.append(
                Observation(
                    probe_id=f"http.v3.{name}",
                    feature=feature,
                    value=value,
                    latency_ms=result.latency_ms,
                    raw=result.raw,
                )
            )
        except BudgetExceeded:
            raise
        except (OSError, http.client.HTTPException) as exc:
            observations.append(_error_observation(f"http.v3.{name}", feature, exc))

    route_matrix: dict[str, dict[str, Any]] = {}
    raw_parts: list[bytes] = []
    latencies: list[float] = []
    for path in V3_ROUTES:
        try:
            result = _request(target, scheduler, port=port, tls=False, method="GET", path=path)
            route_matrix[path] = {
                "status": result.status,
                "location": result.header_map.get("location"),
                "registered": result.status in {301, 302, 303, 307, 308, 401, 403},
            }
            raw_parts.append(result.raw)
            latencies.append(result.latency_ms)
        except BudgetExceeded:
            raise
        except (OSError, http.client.HTTPException) as exc:
            route_matrix[path] = {"state": "unavailable", "error": str(exc)}
    observations.append(
        Observation(
            probe_id="http.v3.route_matrix",
            feature="http.v3.route_matrix",
            value=route_matrix,
            latency_ms=round(sum(latencies), 3) if latencies else None,
            raw=b"\n\n".join(raw_parts),
        )
    )
    return observations
