from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any


class SignatureError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SignatureRule:
    rule_id: str
    feature: str
    matcher: dict[str, Any]
    major: str
    weight: float
    supports: str
    rationale: str
    introduced: str | None = None
    removed: str | None = None
    point_estimate: str | None = None
    hard: bool = False


@dataclass(frozen=True, slots=True)
class SignatureDB:
    schema_version: str
    database_version: str
    generated_at: str
    product: str
    ranges: dict[str, dict[str, str]]
    assets: dict[str, dict[str, Any]]
    rules: tuple[SignatureRule, ...]
    source: str

    @property
    def metadata(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "database_version": self.database_version,
            "generated_at": self.generated_at,
            "source": self.source,
        }


def _load_document(path: Path) -> dict[str, Any]:
    try:
        # JSON is a strict YAML 1.2 subset. Keeping signature files in this subset
        # avoids a mandatory YAML runtime dependency while remaining YAML-compatible.
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SignatureError(f"cannot load signature file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SignatureError(f"signature file {path} must contain an object")
    return value


def _validate_document(document: dict[str, Any], source: str) -> None:
    required = {
        "schema_version": str,
        "database_version": str,
        "generated_at": str,
        "product": str,
        "ranges": dict,
        "assets": dict,
        "rules": list,
    }
    for field, expected_type in required.items():
        if field not in document or not isinstance(document[field], expected_type):
            raise SignatureError(f"{source}: invalid or missing {field}")
    for index, rule in enumerate(document["rules"]):
        if not isinstance(rule, dict):
            raise SignatureError(f"{source}: rules[{index}] must be an object")
        for field in ("id", "feature", "matcher", "major", "weight", "supports", "rationale"):
            if field not in rule:
                raise SignatureError(f"{source}: rules[{index}] missing {field}")
        if not isinstance(rule["matcher"], dict):
            raise SignatureError(f"{source}: rules[{index}].matcher must be an object")
        weight = rule["weight"]
        if not isinstance(weight, (int, float)) or not 0 < float(weight) <= 2:
            raise SignatureError(f"{source}: rules[{index}].weight must be in (0, 2]")


def _to_db(document: dict[str, Any], source: str) -> SignatureDB:
    _validate_document(document, source)
    rules = tuple(
        SignatureRule(
            rule_id=str(rule["id"]),
            feature=str(rule["feature"]),
            matcher=dict(rule["matcher"]),
            major=str(rule["major"]),
            weight=float(rule["weight"]),
            supports=str(rule["supports"]),
            rationale=str(rule["rationale"]),
            introduced=rule.get("introduced"),
            removed=rule.get("removed"),
            point_estimate=rule.get("point_estimate"),
            hard=bool(rule.get("hard", False)),
        )
        for rule in document["rules"]
    )
    return SignatureDB(
        schema_version=str(document["schema_version"]),
        database_version=str(document["database_version"]),
        generated_at=str(document["generated_at"]),
        product=str(document["product"]),
        ranges=dict(document["ranges"]),
        assets=dict(document["assets"]),
        rules=rules,
        source=source,
    )


def load_signatures(directory: Path | None = None) -> SignatureDB:
    if directory is None:
        signature_root = files("plcfp").joinpath("signatures")
        paths = [
            Path(str(signature_root.joinpath("openplc_v3.yaml"))),
            Path(str(signature_root.joinpath("openplc_v4.yaml"))),
        ]
    else:
        paths = sorted(directory.glob("*.yaml"))
        if not paths:
            raise SignatureError(f"no .yaml signatures found in {directory}")
    documents = [_load_document(path) for path in paths]
    for document, path in zip(documents, paths, strict=True):
        _validate_document(document, str(path))
    schema_versions = {str(document["schema_version"]) for document in documents}
    database_versions = {str(document["database_version"]) for document in documents}
    if len(schema_versions) != 1 or len(database_versions) != 1:
        raise SignatureError("all signature files must use the same schema/database version")
    combined = {
        "schema_version": documents[0]["schema_version"],
        "database_version": documents[0]["database_version"],
        "generated_at": max(str(document["generated_at"]) for document in documents),
        "product": "OpenPLC Runtime",
        "ranges": {
            key: value for document in documents for key, value in document["ranges"].items()
        },
        "assets": {
            key: value for document in documents for key, value in document["assets"].items()
        },
        "rules": [rule for document in documents for rule in document["rules"]],
    }
    return _to_db(combined, ",".join(str(path) for path in paths))
