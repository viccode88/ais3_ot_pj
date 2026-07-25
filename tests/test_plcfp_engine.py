from __future__ import annotations

from dataclasses import replace

from plcfp.engine import classify
from plcfp.model import Observation, ProbeState
from plcfp.sigdb import load_signatures


def test_unavailable_is_distinct_from_absent() -> None:
    unavailable = Observation("test.timeout", "tcp.port.8080.open", state=ProbeState.UNAVAILABLE)
    absent = Observation("test.refused", "tcp.port.8080.open", value=False, state=ProbeState.ABSENT)
    assert unavailable.available is False
    assert absent.available is True
    assert unavailable.to_dict()["state"] == "unavailable"
    assert absent.to_dict()["state"] == "absent"


def test_v4_interval_convergence_keeps_evidence() -> None:
    result = classify(
        [
            Observation(
                "http.v4.users_info",
                "http.v4.users_info",
                {"status": 200, "json": []},
            ),
            Observation(
                "http.v4.socketio_handshake",
                "http.v4.socketio_handshake",
                {
                    "engine_io": {"sid": "test", "maxPayload": 1_000_000},
                    "has_max_payload": True,
                },
            ),
        ],
        load_signatures(),
    )
    assert result.major == "v4"
    assert result.version_range == {"min": "4.1.3", "max": "4.1.7"}
    assert result.point_estimate is None
    assert result.lifecycle == "supported"
    assert len(result.evidence) >= 3
    assert result.config_findings


def test_v3_uses_epoch_not_fake_semver() -> None:
    matrix = {f"/route-{index}": {"registered": True, "status": 302} for index in range(5)}
    result = classify(
        [
            Observation(
                "http.v3.login",
                "http.v3.login",
                {
                    "mentions_openplc": True,
                    "has_password_field": True,
                    "release_date": "2022-07-15",
                },
            ),
            Observation("http.v3.route_matrix", "http.v3.route_matrix", matrix),
            Observation(
                "http.v3.style",
                "http.v3.style",
                {"status": 200, "last_modified": "Fri, 15 Jul 2022 12:00:00 GMT"},
            ),
        ],
        load_signatures(),
    )
    assert result.major == "v3"
    assert result.lifecycle == "end-of-life"
    assert result.version_range == {"min": None, "max": None}
    assert result.point_estimate is None
    assert result.build_epoch == "epoch≈2022-Q3 (v3 release marker)"


def test_conflicting_strong_evidence_is_not_forced() -> None:
    result = classify(
        [
            Observation(
                "http.v3.login",
                "http.v3.login",
                {"mentions_openplc": True, "has_password_field": True},
            ),
            Observation(
                "http.v4.users_info",
                "http.v4.users_info",
                {"status": 200},
            ),
        ],
        load_signatures(),
    )
    assert result.major is None
    assert result.status == "CONFLICT"
    assert result.conflicts


def test_complete_asset_baseline_detects_fork() -> None:
    database = load_signatures()
    database = replace(
        database,
        assets={
            **database.assets,
            "v3": {
                "complete": True,
                "features": {"http.v3.style": ["known-official-hash"]},
            },
        },
    )
    result = classify(
        [
            Observation(
                "http.v3.login",
                "http.v3.login",
                {"mentions_openplc": True, "has_password_field": True},
            ),
            Observation(
                "http.v3.style",
                "http.v3.style",
                {"status": 200, "body_sha256": "forked-hash"},
            ),
        ],
        database,
    )
    assert result.major == "v3"
    assert result.status == "FORKED"
    assert "靜態資產" in result.conflicts[-1]
