"""Validated, versioned data models used by the prober.

The models in this module deliberately model our application data, not the
whole Xray configuration language.  Full Xray profiles are kept as opaque JSON
objects so importing and writing them never discards fields unknown to us.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from .safe_regex import MAX_SAFE_NAME_REGEX_LENGTH, validate_safe_name_regex


CURRENT_SCHEMA_VERSION = 1
MAX_DISPLAY_NAME_LENGTH = 160
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def clean_display_name(value: str) -> str:
    """Return a bounded, single-line label safe for terminal display."""

    cleaned = _CONTROL_CHARACTERS.sub("", value).replace("\r", " ").replace("\n", " ")
    cleaned = " ".join(cleaned.split())
    return cleaned[:MAX_DISPLAY_NAME_LENGTH] or "unnamed"


def _validate_id(value: str) -> str:
    if not _SAFE_ID.fullmatch(value):
        raise ValueError("must be 1-128 safe identifier characters")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SourceKind(str, Enum):
    HTTP = "http"
    FILE = "file"
    DIRECTORY = "directory"


SourceType = SourceKind


class SourceFormat(str, Enum):
    AUTO = "auto"
    VLESS = "vless"
    VLESS_BASE64 = "vless_base64"
    XRAY_JSON = "xray_json"
    XRAY_JSON_ARRAY = "xray_json_array"


class EntryKind(str, Enum):
    VLESS_URI = "vless_uri"
    XRAY_JSON = "xray_json"


class CheckMode(str, Enum):
    CONNECTION = "connection"
    PROFILE = "profile"


class RuntimeLifecycle(str, Enum):
    FRESH = "fresh"
    PERSISTENT = "persistent"


RuntimeMode = RuntimeLifecycle


class Compatibility(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    IDENTITY_CONFLICT = "identity_conflict"


class ReachabilityState(str, Enum):
    UNKNOWN = "unknown"
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    STALE = "stale"
    DISABLED = "disabled"


TargetState = ReachabilityState


class EgressState(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"
    ERROR = "error"
    STALE = "stale"
    DISABLED = "disabled"


class Reason(str, Enum):
    CONNECT = "connect"
    PROXY = "proxy"
    DNS = "dns"
    TIMEOUT = "timeout"
    TLS = "tls"
    HTTP_STATUS = "http_status"
    BODY_MISMATCH = "body_mismatch"
    EGRESS_MISMATCH = "egress_mismatch"
    RESPONSE_INVALID = "response_invalid"
    CONFIG_INVALID = "config_invalid"
    UNSUPPORTED = "unsupported"
    RUNTIME_START = "runtime_start"
    RUNTIME_EXIT = "runtime_exit"
    SCHEDULER = "scheduler"
    SOURCE_FETCH = "source_fetch"
    SOURCE_PARSE = "source_parse"
    IDENTITY_CONFLICT = "identity_conflict"
    INTERNAL = "internal"


FailureReason = Reason


class BodyMatchKind(str, Enum):
    EXACT = "exact"
    REGEX = "regex"


class EgressResponseFormat(str, Enum):
    PLAIN = "plain"
    JSON = "json"


class SecretRef(StrictModel):
    """A reference to a secret value; the referenced value is never exported."""

    file: str | None = None
    env: str | None = None

    @model_validator(mode="after")
    def exactly_one_source(self) -> "SecretRef":
        if (self.file is None) == (self.env is None):
            raise ValueError("exactly one of file or env is required")
        if self.file is not None and not self.file.strip():
            raise ValueError("secret file reference must not be empty")
        if self.env is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.env):
            raise ValueError("invalid secret environment variable name")
        return self


class SourceConfig(StrictModel):
    source_id: str
    name: str
    kind: SourceKind
    location: SecretStr | None = Field(default=None, repr=False)
    location_ref: SecretRef | None = None
    format: SourceFormat = SourceFormat.AUTO
    refresh_interval: float = Field(default=300.0, gt=0)
    timeout: float = Field(default=30.0, gt=0)
    max_bytes: int = Field(default=4 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    allow_empty: bool = False
    allow_insecure_http: bool = False
    target_set_ids: list[str] = Field(default_factory=list)
    egress_assertion_ids: list[str] = Field(default_factory=list)
    headers: dict[str, SecretStr] = Field(default_factory=dict, repr=False)
    headers_ref: dict[str, SecretRef] = Field(default_factory=dict)
    enabled: bool = True
    tags: set[str] = Field(default_factory=set)

    @model_validator(mode="before")
    @classmethod
    def accept_explicit_unit_names(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        value = dict(value)
        aliases = {
            "refresh_interval_seconds": "refresh_interval",
            "timeout_seconds": "timeout",
            "max_response_bytes": "max_bytes",
        }
        for old, new in aliases.items():
            if old in value and new not in value:
                value[new] = value.pop(old)
        return value

    @field_validator("source_id")
    @classmethod
    def valid_source_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return clean_display_name(value)

    @field_validator("target_set_ids", "egress_assertion_ids")
    @classmethod
    def valid_reference_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("reference IDs must be unique")
        return [_validate_id(item) for item in values]

    @field_validator("headers", "headers_ref")
    @classmethod
    def valid_header_names(cls, values: dict[str, Any]) -> dict[str, Any]:
        token = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        for name in values:
            if not token.fullmatch(name):
                raise ValueError("invalid HTTP header name")
        return values

    @model_validator(mode="after")
    def valid_location(self) -> "SourceConfig":
        if (self.location is None) == (self.location_ref is None):
            raise ValueError("exactly one of location or location_ref is required")
        overlap = {name.lower() for name in self.headers} & {
            name.lower() for name in self.headers_ref
        }
        if overlap:
            raise ValueError("a header cannot have both an inline value and a secret reference")
        if self.kind is SourceKind.HTTP and self.location is not None:
            raw = self.location.get_secret_value()
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("HTTP source location must be an absolute HTTP(S) URL")
            if parsed.scheme == "http" and not self.allow_insecure_http:
                raise ValueError("plain HTTP source requires allow_insecure_http=true")
        return self

    @property
    def refresh_interval_seconds(self) -> float:
        return self.refresh_interval

    @property
    def timeout_seconds(self) -> float:
        return self.timeout

    @property
    def max_response_bytes(self) -> int:
        return self.max_bytes


class BodyMatcher(StrictModel):
    kind: BodyMatchKind
    value: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def valid_regex(self) -> "BodyMatcher":
        if self.kind is BodyMatchKind.REGEX:
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError("invalid body regular expression") from exc
        return self


class TargetConfig(StrictModel):
    target_id: str
    name: str
    url: str
    method: Literal["GET"] = "GET"
    expected_statuses: set[int] = Field(default_factory=lambda: {200}, min_length=1)
    timeout: float | None = Field(default=None, gt=0)
    body: BodyMatcher | None = None
    max_body_bytes: int = Field(default=64 * 1024, ge=1, le=16 * 1024 * 1024)
    follow_redirects: bool = False
    max_redirects: int = Field(default=0, ge=0, le=20)
    enabled: bool = True

    @model_validator(mode="before")
    @classmethod
    def accept_legacy_names(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        value = dict(value)
        aliases = {
            "expected_status_codes": "expected_statuses",
            "timeout_seconds": "timeout",
        }
        for old, new in aliases.items():
            if old in value and new not in value:
                value[new] = value.pop(old)
        if "body_exact" in value and "body" not in value:
            value["body"] = {"kind": "exact", "value": value.pop("body_exact")}
        if "body_regex" in value and "body" not in value:
            value["body"] = {"kind": "regex", "value": value.pop("body_regex")}
        return value

    @field_validator("target_id")
    @classmethod
    def valid_target_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return clean_display_name(value)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("target URL must be absolute HTTP or HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("target URL must not contain userinfo")
        return value

    @field_validator("expected_statuses")
    @classmethod
    def valid_status_codes(cls, values: set[int]) -> set[int]:
        if any(value < 100 or value > 599 for value in values):
            raise ValueError("expected HTTP statuses must be between 100 and 599")
        return values

    @model_validator(mode="after")
    def valid_redirect_policy(self) -> "TargetConfig":
        if not self.follow_redirects and self.max_redirects:
            raise ValueError("max_redirects requires follow_redirects=true")
        if self.follow_redirects and self.max_redirects == 0:
            object.__setattr__(self, "max_redirects", 5)
        return self

    @property
    def timeout_seconds(self) -> float | None:
        return self.timeout

    @property
    def expected_status_codes(self) -> set[int]:
        return self.expected_statuses


Target = TargetConfig


class TargetSetConfig(StrictModel):
    target_set_id: str
    name: str
    targets: list[TargetConfig] = Field(min_length=1)
    quorum: int = Field(ge=1)
    enabled: bool = True

    @field_validator("target_set_id")
    @classmethod
    def valid_target_set_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return clean_display_name(value)

    @model_validator(mode="after")
    def valid_quorum(self) -> "TargetSetConfig":
        ids = [target.target_id for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("target IDs must be unique within a target set")
        enabled_count = sum(target.enabled for target in self.targets)
        if self.quorum > enabled_count:
            raise ValueError("quorum cannot exceed the number of enabled targets")
        return self


TargetSet = TargetSetConfig


class AssignmentFilter(StrictModel):
    name_glob: str | None = None
    name_regex: str | None = None
    protocol: str | None = None
    transport: str | None = None
    tags: set[str] = Field(default_factory=set)

    @field_validator("name_regex")
    @classmethod
    def valid_name_regex(cls, value: str | None) -> str | None:
        if value is not None:
            validate_safe_name_regex(value)
        return value

    @field_validator("name_glob")
    @classmethod
    def valid_name_glob(cls, value: str | None) -> str | None:
        if value is not None and len(value) > MAX_SAFE_NAME_REGEX_LENGTH:
            raise ValueError(
                f"assignment name_glob exceeds {MAX_SAFE_NAME_REGEX_LENGTH} characters"
            )
        return value


class AssignmentRule(StrictModel):
    assignment_id: str
    # Public, durable identity for a private profile-tag selection. Existing
    # configs derive it from assignment_id; exports persist it after tags are
    # removed so check IDs remain portable.
    selection_id: str | None = None
    entry_id: str | None = None
    source_id: str | None = None
    filter: AssignmentFilter | None = None
    enabled: bool = True
    target_set_ids: list[str] = Field(default_factory=list)
    mode: CheckMode | None = None
    runtime_lifecycle: RuntimeLifecycle | None = None
    outbound_tag: str | None = None
    inbound_tag: str | None = None
    egress_assertion_ids: list[str] = Field(default_factory=list)

    @field_validator("assignment_id", "selection_id", "entry_id", "source_id")
    @classmethod
    def valid_optional_ids(cls, value: str | None) -> str | None:
        return _validate_id(value) if value is not None else None

    @model_validator(mode="after")
    def has_selector(self) -> "AssignmentRule":
        if self.entry_id is None and self.source_id is None and self.filter is None:
            raise ValueError("assignment requires entry_id, source_id, or filter")
        if len(self.target_set_ids) != len(set(self.target_set_ids)):
            raise ValueError("target_set_ids must be unique")
        if len(self.egress_assertion_ids) != len(set(self.egress_assertion_ids)):
            raise ValueError("egress_assertion_ids must be unique")
        return self


AssignmentConfig = AssignmentRule


class EgressAssertionConfig(StrictModel):
    assertion_id: str
    name: str
    url: str
    expected_cidrs: list[str] = Field(min_length=1)
    response_format: EgressResponseFormat = EgressResponseFormat.PLAIN
    json_field: str | None = None
    timeout: float | None = Field(default=None, gt=0)
    enabled: bool = True

    @field_validator("assertion_id")
    @classmethod
    def valid_assertion_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return clean_display_name(value)

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("egress URL must be absolute HTTP or HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("egress URL must not contain userinfo")
        return value

    @field_validator("expected_cidrs")
    @classmethod
    def valid_expected_cidrs(cls, values: list[str]) -> list[str]:
        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError("expected_cidrs contains an invalid network") from exc
        return values

    @model_validator(mode="after")
    def valid_json_field(self) -> "EgressAssertionConfig":
        if self.response_format is EgressResponseFormat.JSON and not self.json_field:
            raise ValueError("json_field is required for a JSON egress response")
        return self


class SchedulerConfig(StrictModel):
    interval: float = Field(default=60.0, gt=0)
    request_timeout: float = Field(default=15.0, gt=0)
    runtime_start_timeout: float = Field(default=10.0, gt=0)
    runtime_restart_backoff_initial: float = Field(default=1.0, ge=0, le=300)
    runtime_restart_backoff_max: float = Field(default=60.0, ge=0, le=3600)
    observatory_warmup_delay: float = Field(default=5.0, ge=0, le=300)
    observatory_warmup_timeout: float = Field(default=30.0, gt=0, le=300)
    max_active_runtimes: int = Field(default=8, ge=1)
    max_parallel_requests: int = Field(default=32, ge=1)
    max_queue_size: int = Field(default=1024, ge=1)
    max_result_age: float = Field(default=180.0, gt=0)

    @model_validator(mode="before")
    @classmethod
    def accept_explicit_unit_names(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        value = dict(value)
        aliases = {
            "interval_seconds": "interval",
            "check_interval_seconds": "interval",
            "request_timeout_seconds": "request_timeout",
            "runtime_start_timeout_seconds": "runtime_start_timeout",
            "runtime_restart_backoff_initial_seconds": (
                "runtime_restart_backoff_initial"
            ),
            "runtime_restart_backoff_max_seconds": "runtime_restart_backoff_max",
            "observatory_warmup_delay_seconds": "observatory_warmup_delay",
            "observatory_warmup_timeout_seconds": "observatory_warmup_timeout",
            "max_result_age_seconds": "max_result_age",
        }
        for old, new in aliases.items():
            if old in value and new not in value:
                value[new] = value.pop(old)
        return value

    @model_validator(mode="after")
    def valid_runtime_timing(self) -> "SchedulerConfig":
        if self.runtime_restart_backoff_initial > self.runtime_restart_backoff_max:
            raise ValueError("initial runtime restart backoff exceeds its maximum")
        if self.observatory_warmup_delay > self.observatory_warmup_timeout:
            raise ValueError("observatory warm-up delay exceeds its timeout")
        return self

    @property
    def interval_seconds(self) -> float:
        return self.interval

    @property
    def check_interval_seconds(self) -> float:
        return self.interval

    @property
    def request_timeout_seconds(self) -> float:
        return self.request_timeout

    @property
    def runtime_start_timeout_seconds(self) -> float:
        return self.runtime_start_timeout

    @property
    def runtime_restart_backoff_initial_seconds(self) -> float:
        return self.runtime_restart_backoff_initial

    @property
    def runtime_restart_backoff_max_seconds(self) -> float:
        return self.runtime_restart_backoff_max

    @property
    def observatory_warmup_delay_seconds(self) -> float:
        return self.observatory_warmup_delay

    @property
    def observatory_warmup_timeout_seconds(self) -> float:
        return self.observatory_warmup_timeout

    @property
    def max_result_age_seconds(self) -> float:
        return self.max_result_age


class ApiConfig(StrictModel):
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)


APIConfig = ApiConfig


class AppConfig(StrictModel):
    schema_version: Literal[CURRENT_SCHEMA_VERSION] = CURRENT_SCHEMA_VERSION
    instance_id: str
    sources: list[SourceConfig] = Field(default_factory=list)
    target_sets: list[TargetSetConfig] = Field(default_factory=list)
    assignments: list[AssignmentRule] = Field(default_factory=list)
    egress_assertions: list[EgressAssertionConfig] = Field(default_factory=list)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    default_target_set_ids: list[str] = Field(default_factory=list)

    @field_validator("instance_id")
    @classmethod
    def valid_instance_id(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def validate_references(self) -> "AppConfig":
        if len(self.default_target_set_ids) != len(set(self.default_target_set_ids)):
            raise ValueError("default_target_set_ids must be unique")
        source_ids = [source.source_id for source in self.sources]
        target_set_ids = [target_set.target_set_id for target_set in self.target_sets]
        assertion_ids = [item.assertion_id for item in self.egress_assertions]
        assignment_ids = [item.assignment_id for item in self.assignments]
        for label, values in (
            ("source", source_ids),
            ("target set", target_set_ids),
            ("egress assertion", assertion_ids),
            ("assignment", assignment_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {label} ID")

        known_sets = set(target_set_ids)
        known_sources = set(source_ids)
        known_assertions = set(assertion_ids)
        for target_set_id in self.default_target_set_ids:
            if target_set_id not in known_sets:
                raise ValueError("default_target_set_ids contains an unknown target set")
        for source in self.sources:
            if not set(source.target_set_ids) <= known_sets:
                raise ValueError("source references an unknown target set")
            if not set(source.egress_assertion_ids) <= known_assertions:
                raise ValueError("source references an unknown egress assertion")
        for assignment in self.assignments:
            if assignment.source_id is not None and assignment.source_id not in known_sources:
                raise ValueError("assignment references an unknown source")
            if not set(assignment.target_set_ids) <= known_sets:
                raise ValueError("assignment references an unknown target set")
            if not set(assignment.egress_assertion_ids) <= known_assertions:
                raise ValueError("assignment references an unknown egress assertion")
        return self


class ImportedEntry(StrictModel):
    """A parsed candidate before it receives a persistent public entry ID."""

    candidate_id: str
    source_id: str | None = None
    name: str
    kind: EntryKind
    mode: CheckMode
    payload: str | dict[str, Any] | None = Field(default=None, repr=False)
    profile: dict[str, Any] | None = Field(default=None, repr=False)
    outbound_tag: str | None = None
    inbound_tag: str | None = None
    external_id: str | None = Field(default=None, repr=False)
    protocol: str = "vless"
    transport: str | None = None
    security: str | None = None
    compatibility: Compatibility = Compatibility.SUPPORTED
    compatibility_reason: str | None = None
    identity_name: str
    connection_fingerprint: str | None = Field(default=None, repr=False)
    safe_display: str
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("candidate_id")
    @classmethod
    def valid_candidate_id(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name", "identity_name", "safe_display")
    @classmethod
    def valid_display_text(cls, value: str) -> str:
        return clean_display_name(value)

    @model_validator(mode="after")
    def require_private_definition(self) -> "ImportedEntry":
        if self.payload is None and self.profile is None:
            raise ValueError("imported entry requires payload or profile")
        return self

    def to_entry_record(self, entry_id: str, generation: str) -> "EntryRecord":
        return EntryRecord(
            entry_id=entry_id,
            source_id=self.source_id or "unassigned",
            name=self.name,
            kind=self.kind,
            mode=self.mode,
            # JSON profiles are already retained losslessly in ``profile``;
            # storing the same object again can nearly double an LKG file.
            payload=None if self.profile is not None else self.payload,
            profile=self.profile,
            outbound_tag=self.outbound_tag,
            inbound_tag=self.inbound_tag,
            generation=generation,
            compatibility=self.compatibility,
            compatibility_reason=self.compatibility_reason,
            protocol=self.protocol,
            transport=self.transport,
            security=self.security,
            external_id=self.external_id,
            identity_name=self.identity_name,
            connection_fingerprint=self.connection_fingerprint,
            safe_display=self.safe_display,
            metadata=self.metadata,
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_id": self.source_id,
            "name": self.name,
            "kind": self.kind.value,
            "mode": self.mode.value,
            "protocol": self.protocol,
            "transport": self.transport,
            "security": self.security,
            "compatibility": self.compatibility.value,
            "compatibility_reason": self.compatibility_reason,
            "safe_display": self.safe_display,
        }


class EntryRecord(StrictModel):
    entry_id: str
    source_id: str
    name: str
    kind: EntryKind = EntryKind.VLESS_URI
    mode: CheckMode
    payload: str | dict[str, Any] | None = Field(default=None, repr=False)
    profile: dict[str, Any] | None = Field(default=None, repr=False)
    outbound_tag: str | None = None
    inbound_tag: str | None = None
    generation: str
    enabled: bool = True
    compatibility: Compatibility = Compatibility.SUPPORTED
    compatibility_reason: str | None = None
    protocol: str = "vless"
    transport: str | None = None
    security: str | None = None
    external_id: str | None = Field(default=None, repr=False)
    identity_name: str | None = Field(default=None, repr=False)
    connection_fingerprint: str | None = Field(default=None, repr=False)
    safe_display: str | None = None
    tags: set[str] = Field(default_factory=set)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("entry_id", "source_id", "generation")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _validate_id(value)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return clean_display_name(value)

    @model_validator(mode="after")
    def fill_safe_display(self) -> "EntryRecord":
        if self.payload is None and self.profile is None:
            raise ValueError("entry requires payload or profile")
        if self.safe_display is None:
            details = "/".join(part for part in (self.protocol, self.transport, self.security) if part)
            object.__setattr__(
                self,
                "safe_display",
                f"{self.name} ({details})" if details else self.name,
            )
        else:
            object.__setattr__(self, "safe_display", clean_display_name(self.safe_display))
        return self

    def public_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "source_id": self.source_id,
            "name": self.name,
            "kind": self.kind.value,
            "mode": self.mode.value,
            "generation": self.generation,
            "enabled": self.enabled,
            "compatibility": self.compatibility.value,
            "compatibility_reason": self.compatibility_reason,
            "protocol": self.protocol,
            "transport": self.transport,
            "security": self.security,
            "safe_display": self.safe_display,
            "tags": sorted(self.tags),
        }


Entry = EntryRecord


class CheckDefinition(StrictModel):
    check_id: str
    entry_id: str
    source_id: str
    target_set_id: str
    mode: CheckMode
    generation: str
    outbound_tag: str | None = None
    inbound_tag: str | None = None
    runtime_lifecycle: RuntimeLifecycle | None = None
    egress_assertion_ids: list[str] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("check_id", "entry_id", "source_id", "target_set_id", "generation")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _validate_id(value)

    @model_validator(mode="after")
    def default_lifecycle(self) -> "CheckDefinition":
        if self.runtime_lifecycle is None:
            object.__setattr__(
                self,
                "runtime_lifecycle",
                RuntimeLifecycle.FRESH
                if self.mode is CheckMode.CONNECTION
                else RuntimeLifecycle.PERSISTENT,
            )
        return self


Check = CheckDefinition


class TargetResult(StrictModel):
    target_id: str
    state: ReachabilityState
    success: bool | None = None
    reason: Reason | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    duration_seconds: float | None = Field(default=None, ge=0)
    ttfb_seconds: float | None = Field(default=None, ge=0)
    bytes_read: int | None = Field(default=None, ge=0)
    error: str | None = Field(default=None, max_length=240)

    @model_validator(mode="before")
    @classmethod
    def accept_status_code(cls, value: Any) -> Any:
        if isinstance(value, dict) and "status_code" in value and "http_status" not in value:
            value = dict(value)
            value["http_status"] = value.pop("status_code")
        return value

    @model_validator(mode="after")
    def coherent_success(self) -> "TargetResult":
        expected = {
            ReachabilityState.SUCCESS: True,
            ReachabilityState.FAILURE: False,
        }.get(self.state)
        if self.success is None:
            object.__setattr__(self, "success", expected)
        elif expected is not None and self.success is not expected:
            raise ValueError("success is inconsistent with target state")
        return self

    @property
    def status_code(self) -> int | None:
        return self.http_status


TargetProbeResult = TargetResult


class ReachabilityResult(StrictModel):
    state: ReachabilityState
    success_count: int = Field(ge=0)
    quorum: int = Field(ge=1)
    targets: list[TargetResult]


class EgressResult(StrictModel):
    assertion_id: str
    state: EgressState
    reason: Reason | None = None
    observed_ip: str | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    error: str | None = Field(default=None, max_length=240)


EgressProbeResult = EgressResult


class CycleResult(StrictModel):
    check_id: str
    generation: str
    reachability: ReachabilityResult
    egress: list[EgressResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)


class RunResult(StrictModel):
    run_id: str
    check_id: str
    instance_id: str
    source_id: str
    entry_id: str
    mode: CheckMode
    target_set_id: str
    generation: str
    # Private persisted CAS token for the effective application configuration.
    # It is deliberately omitted from all public result/snapshot renderers.
    config_revision: str | None = Field(default=None, repr=False)
    state: ReachabilityState
    running: bool = False
    started_at: datetime
    completed_at: datetime | None = None
    success_count: int = Field(default=0, ge=0)
    quorum: int = Field(default=1, ge=1)
    target_results: list[TargetResult] = Field(default_factory=list)
    egress_results: list[EgressResult] = Field(default_factory=list)
    reason: Reason | None = None
    error: str | None = Field(default=None, max_length=240)

    @field_validator(
        "run_id", "check_id", "instance_id", "source_id", "entry_id",
        "target_set_id", "generation", "config_revision",
    )
    @classmethod
    def valid_ids(cls, value: str | None) -> str | None:
        return _validate_id(value) if value is not None else None

    @model_validator(mode="after")
    def valid_times(self) -> "RunResult":
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("completed_at cannot precede started_at")
        return self


CheckResult = RunResult


class SourceGeneration(StrictModel):
    schema_version: Literal[CURRENT_SCHEMA_VERSION] = CURRENT_SCHEMA_VERSION
    source_id: str
    generation: str
    accepted_at: datetime = Field(default_factory=utc_now)
    entries: list[EntryRecord]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_id", "generation")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        return _validate_id(value)


class IdentityBindingModel(StrictModel):
    entry_id: str
    external_id: str | None = Field(default=None, repr=False)
    name_key: str | None = Field(default=None, repr=False)
    connection_fingerprint: str | None = Field(default=None, repr=False)
    active: bool = True


class IdentityRegistryModel(StrictModel):
    schema_version: Literal[CURRENT_SCHEMA_VERSION] = CURRENT_SCHEMA_VERSION
    sources: dict[str, list[IdentityBindingModel]] = Field(default_factory=dict)


__all__ = [
    "APIConfig",
    "ApiConfig",
    "AppConfig",
    "AssignmentConfig",
    "AssignmentFilter",
    "AssignmentRule",
    "BodyMatchKind",
    "BodyMatcher",
    "CURRENT_SCHEMA_VERSION",
    "Check",
    "CheckDefinition",
    "CheckMode",
    "CheckResult",
    "Compatibility",
    "CycleResult",
    "EgressAssertionConfig",
    "EgressProbeResult",
    "EgressResponseFormat",
    "EgressResult",
    "EgressState",
    "Entry",
    "EntryKind",
    "EntryRecord",
    "FailureReason",
    "IdentityBindingModel",
    "IdentityRegistryModel",
    "ImportedEntry",
    "ReachabilityResult",
    "ReachabilityState",
    "Reason",
    "RunResult",
    "RuntimeLifecycle",
    "RuntimeMode",
    "SchedulerConfig",
    "SecretRef",
    "SourceConfig",
    "SourceFormat",
    "SourceGeneration",
    "SourceKind",
    "SourceType",
    "Target",
    "TargetConfig",
    "TargetProbeResult",
    "TargetResult",
    "TargetSet",
    "TargetSetConfig",
    "TargetState",
    "clean_display_name",
    "utc_now",
]
