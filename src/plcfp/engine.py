from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any

from plcfp.model import Evidence, Observation, ProbeState
from plcfp.sigdb import SignatureDB, SignatureRule


def _get_path(value: Any, path: str | None) -> Any:
    if not path:
        return value
    current = value
    for component in path.split("."):
        if not isinstance(current, dict) or component not in current:
            return None
        current = current[component]
    return current


def _match(value: Any, matcher: dict[str, Any]) -> bool:
    candidate = _get_path(value, matcher.get("path"))
    operation = matcher.get("op", "eq")
    expected = matcher.get("value")
    if operation == "eq":
        return bool(candidate == expected)
    if operation == "in":
        return candidate in expected if isinstance(expected, list) else False
    if operation == "contains":
        if not isinstance(candidate, (str, list, tuple, dict)):
            return False
        return str(expected).lower() in str(candidate).lower()
    if operation == "regex":
        return isinstance(candidate, str) and re.search(str(expected), candidate) is not None
    if operation == "exists":
        return candidate is not None
    if operation == "truthy":
        return bool(candidate)
    if operation == "registered_count_gte":
        if not isinstance(candidate, dict) or not isinstance(expected, (int, str)):
            return False
        count = sum(
            1 for item in candidate.values() if isinstance(item, dict) and item.get("registered")
        )
        return count >= int(expected)
    if operation == "all_responded":
        return (
            isinstance(candidate, dict)
            and bool(candidate)
            and all(
                isinstance(item, dict) and item.get("responded") is True
                for item in candidate.values()
            )
        )
    raise ValueError(f"unsupported signature matcher operation: {operation}")


def _version_key(value: str) -> tuple[int, ...]:
    match = re.findall(r"\d+", value)
    return tuple(int(part) for part in match)


@dataclass(slots=True)
class EngineResult:
    product: str | None
    major: str | None
    version_range: dict[str, str | None]
    point_estimate: str | None
    build_epoch: str | None
    confidence: float
    lifecycle: str
    cpe: list[str]
    evidence: list[Evidence]
    conflicts: list[str]
    config_findings: list[str]
    status: str


def _build_epoch(observations: list[Observation]) -> str | None:
    for observation in observations:
        if observation.feature != "http.v3.login" or not isinstance(observation.value, dict):
            continue
        release_date = observation.value.get("release_date")
        if not isinstance(release_date, str):
            continue
        match = re.fullmatch(r"(\d{4})-(\d{2})-\d{2}", release_date)
        if match:
            quarter = (int(match.group(2)) - 1) // 3 + 1
            return f"epoch≈{match.group(1)}-Q{quarter} (v3 release marker)"
    for observation in observations:
        if observation.feature not in {
            "http.v3.style",
            "http.v3.logo",
            "http.v3.roboto_css",
        } or not isinstance(observation.value, dict):
            continue
        raw_date = observation.value.get("last_modified")
        if not isinstance(raw_date, str):
            continue
        try:
            timestamp = parsedate_to_datetime(raw_date)
        except (TypeError, ValueError):
            continue
        quarter = (timestamp.month - 1) // 3 + 1
        return f"deployment≈{timestamp.year}-Q{quarter} (static asset mtime)"
    return None


def _config_findings(observations: list[Observation]) -> list[str]:
    findings: list[str] = []
    for observation in observations:
        if observation.feature != "http.v4.users_info" or not isinstance(observation.value, dict):
            continue
        if observation.value.get("status") == 200:
            findings.append("/api/get-users-info 可在未認證狀態存取")
        if observation.value.get("setup_incomplete"):
            findings.append("使用者資訊為空；請人工確認首次設定與 /api/create-user 暴露風險")
    return findings


def _fork_reason(
    major: str | None,
    observations: list[Observation],
    database: SignatureDB,
    score: float,
) -> str | None:
    if major is None or score < 1.2:
        return None
    definition = database.assets.get(major)
    if not isinstance(definition, dict) or definition.get("complete") is not True:
        return None
    features = definition.get("features")
    if not isinstance(features, dict):
        return None
    mismatches: list[str] = []
    matches = 0
    for observation in observations:
        expected = features.get(observation.feature)
        if not isinstance(expected, list) or not expected:
            continue
        if not isinstance(observation.value, dict):
            continue
        actual = observation.value.get("body_sha256")
        if not isinstance(actual, str):
            continue
        if actual in expected:
            matches += 1
        else:
            mismatches.append(f"{observation.feature}={actual}")
    if mismatches and matches == 0:
        return "行為/路由命中已知 OpenPLC 世代，但靜態資產不符合完整官方基準：" + ", ".join(
            mismatches
        )
    return None


def classify(observations: list[Observation], database: SignatureDB) -> EngineResult:
    matched: list[tuple[SignatureRule, Observation]] = []
    scores = {"v3": 0.0, "v4": 0.0}
    hard_excluded: set[str] = set()
    for observation in observations:
        if observation.state != ProbeState.OBSERVED:
            continue
        for rule in database.rules:
            if rule.feature != observation.feature:
                continue
            if _match(observation.value, rule.matcher):
                matched.append((rule, observation))
                scores[rule.major] = scores.get(rule.major, 0.0) + rule.weight
            elif rule.hard:
                hard_excluded.add(rule.major)
    for excluded in hard_excluded:
        scores[excluded] = 0.0

    conflicts: list[str] = []
    strong = [major for major, score in scores.items() if score >= 1.2]
    if len(strong) > 1:
        conflicts.append("同時觀測到 v3 與 v4 的強證據；可能是多服務主機、代理轉送或客製化 fork")
        status = "CONFLICT"
        major = None
    else:
        winner = max(scores, key=lambda candidate: scores[candidate])
        major = winner if scores[winner] >= 0.8 else None
        status = "complete" if major else "INCONCLUSIVE"

    winning_score = scores.get(major, 0.0) if major else 0.0
    losing_score = max((score for key, score in scores.items() if key != major), default=0.0)
    if major:
        confidence = min(0.99, (0.35 + 0.12 * winning_score) / (1 + 0.15 * losing_score))
    else:
        confidence = 0.0

    selected = [(rule, obs) for rule, obs in matched if rule.major == major]
    evidence = [
        Evidence(
            probe=observation.probe_id,
            feature=observation.feature,
            value=observation.value,
            weight=rule.weight,
            supports=rule.supports,
            rationale=rule.rationale,
        )
        for rule, observation in sorted(selected, key=lambda item: item[0].weight, reverse=True)
    ]

    minimum: str | None = None
    maximum: str | None = None
    point_estimate: str | None = None
    if major and major in database.ranges:
        minimum = database.ranges[major].get("min")
        maximum = database.ranges[major].get("max")
        for rule, _ in selected:
            if rule.introduced and (
                minimum is None or _version_key(rule.introduced) > _version_key(minimum)
            ):
                minimum = rule.introduced
            if rule.removed and (
                maximum is None or _version_key(rule.removed) < _version_key(maximum)
            ):
                maximum = rule.removed
            if rule.point_estimate:
                point_estimate = rule.point_estimate
        if minimum and maximum and _version_key(minimum) > _version_key(maximum):
            conflicts.append("版本規則的區間交集為空")
            status = "CONFLICT"
            point_estimate = None

    if major == "v3":
        minimum = maximum = point_estimate = None
        lifecycle = "end-of-life"
        build_epoch = _build_epoch(observations)
    elif major == "v4":
        lifecycle = "supported"
        build_epoch = None
    else:
        lifecycle = "unknown"
        build_epoch = None

    fork_reason = _fork_reason(major, observations, database, winning_score)
    if fork_reason:
        conflicts.append(fork_reason)
        status = "FORKED"
        point_estimate = None

    cpe: list[str] = []
    if major == "v4" and point_estimate:
        cpe = [
            f"cpe:2.3:a:autonomylogic:openplc_runtime:{point_estimate}:*:*:*:*:*:*:*",
            f"cpe:2.3:a:thiagoralves:openplc_runtime:{point_estimate}:*:*:*:*:*:*:*",
        ]
    elif major == "v3":
        cpe = [
            "cpe:2.3:a:thiagoralves:openplc_runtime:3:*:*:*:*:*:*:*",
            "cpe:2.3:a:autonomylogic:openplc_runtime:3:*:*:*:*:*:*:*",
        ]

    return EngineResult(
        product=database.product if major else None,
        major=major,
        version_range={"min": minimum, "max": maximum},
        point_estimate=point_estimate,
        build_epoch=build_epoch,
        confidence=round(confidence, 3),
        lifecycle=lifecycle,
        cpe=cpe,
        evidence=evidence,
        conflicts=conflicts,
        config_findings=_config_findings(observations),
        status=status,
    )
