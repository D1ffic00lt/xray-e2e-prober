"""Safe YAML loading, validation, redacted export and atomic persistence."""

from __future__ import annotations

import os
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import BaseModel, SecretStr, ValidationError

from .models import AppConfig, CURRENT_SCHEMA_VERSION, SecretRef, SourceConfig
from .storage import atomic_write_text


MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_YAML_ALIASES = 50
REDACTED = "<redacted>"


class ConfigError(ValueError):
    reason = "config_invalid"


class ConfigLoadError(ConfigError):
    pass


class ConfigValidationError(ConfigError):
    pass


class _UniqueSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that rejects duplicate mappings and alias floods."""

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._alias_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):
            self._alias_count += 1
            if self._alias_count > MAX_YAML_ALIASES:
                raise yaml.constructor.ConstructorError(
                    None, None, "too many YAML aliases", self.peek_event().start_mark
                )
        return super().compose_node(parent, index)


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _validation_message(exc: ValidationError) -> str:
    messages: list[str] = []
    for error in exc.errors(include_url=False, include_input=False):
        location = ".".join(str(part) for part in error.get("loc", ())) or "config"
        messages.append(f"{location}: {error.get('msg', 'invalid value')}")
    return "; ".join(messages[:20]) or "configuration is invalid"


def _safe_yaml_load(text: str) -> Any:
    try:
        return yaml.load(text, Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ConfigLoadError("configuration is not valid safe YAML") from exc


def loads_config(text: str | bytes, *, max_bytes: int = MAX_CONFIG_BYTES) -> AppConfig:
    if isinstance(text, bytes):
        if len(text) > max_bytes:
            raise ConfigLoadError("configuration exceeds size limit")
        try:
            decoded = text.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ConfigLoadError("configuration is not valid UTF-8") from exc
    elif isinstance(text, str):
        if len(text.encode("utf-8")) > max_bytes:
            raise ConfigLoadError("configuration exceeds size limit")
        decoded = text.lstrip("\ufeff")
    else:
        raise TypeError("configuration must be str or bytes")
    value = _safe_yaml_load(decoded)
    return validate_config(value)


def load_config(
    path: str | os.PathLike[str], *, max_bytes: int = MAX_CONFIG_BYTES
) -> AppConfig:
    config_path = Path(path)
    try:
        size = config_path.stat().st_size
        if size > max_bytes:
            raise ConfigLoadError("configuration exceeds size limit")
        data = config_path.read_bytes()
    except ConfigError:
        raise
    except FileNotFoundError as exc:
        raise ConfigLoadError("configuration file does not exist") from exc
    except OSError as exc:
        raise ConfigLoadError("configuration file cannot be read") from exc
    return loads_config(data, max_bytes=max_bytes)


def validate_config(value: AppConfig | Mapping[str, Any] | Any) -> AppConfig:
    if isinstance(value, AppConfig):
        return value
    if not isinstance(value, Mapping):
        raise ConfigValidationError("configuration root must be a mapping")
    if "schema_version" not in value:
        raise ConfigValidationError("schema_version is required")
    if value.get("schema_version") != CURRENT_SCHEMA_VERSION:
        raise ConfigValidationError(
            f"unsupported schema_version; expected {CURRENT_SCHEMA_VERSION}"
        )
    try:
        return AppConfig.model_validate(value)
    except ValidationError as exc:
        raise ConfigValidationError(_validation_message(exc)) from exc


def _serialize(value: Any, *, reveal_secrets: bool) -> Any:
    if isinstance(value, SecretStr):
        return value.get_secret_value() if reveal_secrets else REDACTED
    if isinstance(value, BaseModel):
        return {
            key: _serialize(item, reveal_secrets=reveal_secrets)
            for key, item in value.model_dump(mode="python").items()
        }
    if isinstance(value, Mapping):
        return {
            str(key): _serialize(item, reveal_secrets=reveal_secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_serialize(item, reveal_secrets=reveal_secrets) for item in value]
    if isinstance(value, set):
        serialized = [_serialize(item, reveal_secrets=reveal_secrets) for item in value]
        return sorted(serialized, key=str)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def config_to_dict(config: AppConfig, *, reveal_secrets: bool = False) -> dict[str, Any]:
    value = _serialize(config, reveal_secrets=reveal_secrets)
    if not isinstance(value, dict):
        raise TypeError("configuration did not serialize to a mapping")
    return value


def dump_config(config: AppConfig, *, reveal_secrets: bool = True) -> str:
    """Serialize validated YAML. Persistence reveals values; export does not."""

    try:
        return yaml.safe_dump(
            config_to_dict(config, reveal_secrets=reveal_secrets),
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
    except yaml.YAMLError as exc:
        raise ConfigError("configuration cannot be serialized") from exc


def save_config(
    config: AppConfig | Mapping[str, Any],
    path: str | os.PathLike[str],
    *,
    mode: int = 0o600,
) -> AppConfig:
    validated = validate_config(config)
    atomic_write_text(path, dump_config(validated, reveal_secrets=True), mode=mode)
    return validated


def export_config_dict(config: AppConfig | Mapping[str, Any]) -> dict[str, Any]:
    """Return portable structure with mappings/IDs but no inline secret values."""

    validated = validate_config(config)
    exported = config_to_dict(validated, reveal_secrets=False)
    # Inline locations and headers are deliberately unusable placeholders.
    # Existing references remain intact and can be populated on another host.
    for source in exported.get("sources", []):
        if source.get("location_ref") is not None:
            source["location"] = None
        elif source.get("location") is not None:
            source["location"] = REDACTED
        if source.get("headers_ref"):
            for name in list(source.get("headers", {})):
                if name in source["headers_ref"]:
                    source["headers"].pop(name, None)
        for name in list(source.get("headers", {})):
            source["headers"][name] = REDACTED
    # Profile tags are arbitrary source-controlled strings and may themselves
    # contain private material. Stable assignment IDs preserve check identity;
    # operators re-enter tag selectors with the destination profile.
    for assignment in exported.get("assignments", []):
        if (
            assignment.get("selection_id") is None
            and (
                assignment.get("outbound_tag") is not None
                or assignment.get("inbound_tag") is not None
            )
        ):
            assignment["selection_id"] = assignment["assignment_id"]
        assignment["outbound_tag"] = None
        assignment["inbound_tag"] = None
    return exported


def export_config(
    config: AppConfig | Mapping[str, Any],
    path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    exported = export_config_dict(config)
    if path is not None:
        try:
            text = yaml.safe_dump(
                exported,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        except yaml.YAMLError as exc:
            raise ConfigError("configuration export cannot be serialized") from exc
        atomic_write_text(path, text, mode=0o600)
    return exported


def export_config_yaml(config: AppConfig | Mapping[str, Any]) -> str:
    try:
        return yaml.safe_dump(
            export_config_dict(config),
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        )
    except yaml.YAMLError as exc:
        raise ConfigError("configuration export cannot be serialized") from exc


def resolve_secret_ref(
    reference: SecretRef,
    *,
    environ: Mapping[str, str] | None = None,
    base_dir: str | os.PathLike[str] | None = None,
    max_bytes: int = 1024 * 1024,
) -> str:
    if reference.env is not None:
        values = os.environ if environ is None else environ
        try:
            return values[reference.env]
        except KeyError as exc:
            raise ConfigError("referenced secret environment variable is not set") from exc
    assert reference.file is not None
    path = Path(reference.file)
    if not path.is_absolute() and base_dir is not None:
        path = Path(base_dir) / path
    try:
        if path.stat().st_size > max_bytes:
            raise ConfigError("referenced secret file exceeds size limit")
        raw = path.read_bytes()
    except ConfigError:
        raise
    except OSError as exc:
        raise ConfigError("referenced secret file cannot be read") from exc
    try:
        # Docker/Kubernetes secret files conventionally end with one newline.
        return raw.decode("utf-8").removesuffix("\n")
    except UnicodeDecodeError as exc:
        raise ConfigError("referenced secret file is not valid UTF-8") from exc


def resolve_source_location(
    source: SourceConfig,
    *,
    environ: Mapping[str, str] | None = None,
    base_dir: str | os.PathLike[str] | None = None,
) -> str:
    if source.location is not None:
        return source.location.get_secret_value()
    assert source.location_ref is not None
    return resolve_secret_ref(source.location_ref, environ=environ, base_dir=base_dir)


def resolve_source_headers(
    source: SourceConfig,
    *,
    environ: Mapping[str, str] | None = None,
    base_dir: str | os.PathLike[str] | None = None,
) -> dict[str, str]:
    values = {name: value.get_secret_value() for name, value in source.headers.items()}
    for name, reference in source.headers_ref.items():
        values[name] = resolve_secret_ref(reference, environ=environ, base_dir=base_dir)
    return values


__all__ = [
    "ConfigError",
    "ConfigLoadError",
    "ConfigValidationError",
    "MAX_CONFIG_BYTES",
    "REDACTED",
    "config_to_dict",
    "dump_config",
    "export_config",
    "export_config_dict",
    "export_config_yaml",
    "load_config",
    "loads_config",
    "resolve_secret_ref",
    "resolve_source_headers",
    "resolve_source_location",
    "save_config",
    "validate_config",
]
