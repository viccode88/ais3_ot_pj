"""External plugin discovery through Python entry points."""

from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any


@dataclass(frozen=True)
class PluginInfo:
    name: str
    value: str


def discover() -> list[PluginInfo]:
    return [PluginInfo(item.name, item.value) for item in entry_points(group="modbus_cli.plugins")]


def load(name: str) -> Any:
    for item in entry_points(group="modbus_cli.plugins"):
        if item.name == name:
            return item.load()
    raise LookupError(f"plugin {name!r} is not installed")


def validate(name: str) -> tuple[bool, str]:
    plugin = load(name)
    missing = [attribute for attribute in ("name", "api_version") if not hasattr(plugin, attribute)]
    return (not missing, "valid" if not missing else f"missing: {', '.join(missing)}")
