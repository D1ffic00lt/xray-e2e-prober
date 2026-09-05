"""Typer command line interface and prompt-toolkit setup wizards."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

import typer
import uvicorn
import yaml
from prompt_toolkit import prompt as terminal_prompt

from .api import create_app
from .config import config_to_dict, export_config_dict, load_config
from .control import ControlError, control_available, request as control_request
from .identity import (
    new_source_id,
    new_target_id,
    new_target_set_id,
)
from .importers import safe_reconciliation_fingerprint
from .inventory import compile_inventory
from .logging_config import configure_logging
from .models import (
    AppConfig,
    AssignmentFilter,
    AssignmentRule,
    BodyMatcher,
    Compatibility,
    EgressAssertionConfig,
    SchedulerConfig,
    SecretRef,
    SourceConfig,
    SourceFormat,
    SourceKind,
    TargetConfig,
    TargetSetConfig,
)
from .security import redact_text
from .service import ProberService, ServiceError, fetch_source_candidates
from .sources import SourceLoader
from .storage import DataStore, StorageError, atomic_write_text


app = typer.Typer(
    name="prober",
    help="End-to-end checks for Xray subscriptions and client profiles.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
subscription_app = typer.Typer(help="Manage subscription and local sources.")
entries_app = typer.Typer(help="Inspect imported entries and reconcile identities.")
targets_app = typer.Typer(help="Create and edit target sets.")
assignments_app = typer.Typer(help="Edit bulk assignments, exclusions, and filters.")
egress_app = typer.Typer(help="Create and edit optional egress IP assertions.")
check_app = typer.Typer(help="Run checks once.")
config_app = typer.Typer(help="Validate and export configuration.")
app.add_typer(subscription_app, name="subscription")
app.add_typer(entries_app, name="entries")
app.add_typer(targets_app, name="targets")
app.add_typer(assignments_app, name="assignments")
app.add_typer(egress_app, name="egress")
app.add_typer(check_app, name="check")
app.add_typer(config_app, name="config")


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Paths:
    data_dir: Path
    config_path: Path
    xray_binary: str

    @property
    def control_path(self) -> Path:
        return self.data_dir / "control.sock"


@dataclass(slots=True)
class SourceDraft:
    source: SourceConfig
    candidates: list[Any]
    location_value: str
    header_values: dict[str, str]


def _paths(
    data_dir: Path | None = None,
    config_path: Path | None = None,
    xray_binary: str | None = None,
) -> Paths:
    root = Path(data_dir or os.environ.get("PROBER_DATA_DIR", "./data")).expanduser()
    config = Path(
        config_path or os.environ.get("PROBER_CONFIG", root / "config.yaml")
    ).expanduser()
    return Paths(root.resolve(), config.resolve(), xray_binary or os.environ.get("XRAY_BINARY", "xray"))


def _run(awaitable: Awaitable[T]) -> T:
    return asyncio.run(awaitable)


def _fail(exc: BaseException | str, *, code: int = 2) -> None:
    typer.echo(f"error: {redact_text(exc, max_length=320)}", err=True)
    raise typer.Exit(code=code)


def _emit(value: Any, *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(value, ensure_ascii=False, indent=2, default=str))
        return
    if isinstance(value, str):
        typer.echo(value)
        return
    if isinstance(value, list):
        if not value:
            typer.echo("(none)")
            return
        for item in value:
            if isinstance(item, dict):
                typer.echo("  ".join(f"{key}={val}" for key, val in item.items()))
            else:
                typer.echo(str(item))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                typer.echo(f"{key}: {json.dumps(item, ensure_ascii=False, default=str)}")
            else:
                typer.echo(f"{key}: {item}")
        return
    typer.echo(str(value))


def _ask(label: str, *, default: str = "", secret: bool = False) -> str:
    try:
        return terminal_prompt(label, default=default, is_password=secret).strip()
    except (EOFError, KeyboardInterrupt):
        raise typer.Abort() from None


def _confirm(label: str, *, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        answer = _ask(label + suffix).casefold()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False
        typer.echo("Enter yes or no.")


def _ask_float(label: str, default: float, *, minimum: float = 0.001) -> float:
    while True:
        raw = _ask(label, default=str(default))
        try:
            value = float(raw)
        except ValueError:
            typer.echo("Enter a number.")
            continue
        if value >= minimum:
            return value
        typer.echo(f"Value must be at least {minimum}.")


def _ask_int(label: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    while True:
        raw = _ask(label, default=str(default))
        try:
            value = int(raw)
        except ValueError:
            typer.echo("Enter an integer.")
            continue
        if value < minimum or (maximum is not None and value > maximum):
            typer.echo(f"Value must be between {minimum} and {maximum or '∞'}.")
            continue
        return value


def _select_indices(
    label: str,
    count: int,
    *,
    default_all: bool,
) -> set[int]:
    default = "all" if default_all else ""
    while True:
        raw = _ask(label, default=default).casefold()
        if raw in {"all", "*", "все"}:
            return set(range(count))
        if raw in {"none", "нет", "-"} or (not raw and not default_all):
            return set()
        try:
            values = {
                int(part.strip()) - 1
                for part in raw.replace(";", ",").split(",")
                if part.strip()
            }
        except ValueError:
            typer.echo("Enter comma-separated item numbers, 'all', or 'none'.")
            continue
        if values and min(values) >= 0 and max(values) < count:
            return values
        typer.echo("Selection contains an invalid item number.")


async def _control_or_service(
    paths: Paths,
    command: str,
    params: dict[str, Any] | None = None,
) -> Any:
    if await control_available(paths.control_path):
        return await control_request(paths.control_path, command, params, timeout=600)
    service = ProberService(
        paths.data_dir,
        config_path=paths.config_path,
        xray_binary=paths.xray_binary,
        schedule_enabled=False,
        control_enabled=False,
    )
    await service.start()
    try:
        return await service.handle_control(command, params or {})
    finally:
        await service.stop()


async def _apply_config(
    paths: Paths,
    config: AppConfig,
    *,
    expected_revision: str | None = None,
    secrets: dict[str, str] | None = None,
) -> None:
    value = config_to_dict(config, reveal_secrets=True)
    await _control_or_service(
        paths,
        "apply_config",
        {
            "config": value,
            "expected_revision": expected_revision,
            "secrets": secrets or {},
        },
    )


async def _config_for_edit(paths: Paths) -> tuple[AppConfig, str]:
    response = await _control_or_service(paths, "config_for_edit")
    revision = response.get("revision")
    value = response.get("config")
    if not isinstance(revision, str) or not isinstance(value, dict):
        raise ServiceError("daemon returned an invalid editable configuration")
    return AppConfig.model_validate(value), revision


def _load_existing(paths: Paths, *, required: bool = True) -> AppConfig | None:
    if not paths.config_path.exists():
        if required:
            raise ServiceError("configuration does not exist; run 'prober setup' first")
        return None
    return load_config(paths.config_path)


def _source_kind() -> SourceKind:
    choices = {
        "url": SourceKind.HTTP,
        "http": SourceKind.HTTP,
        "file": SourceKind.FILE,
        "directory": SourceKind.DIRECTORY,
        "dir": SourceKind.DIRECTORY,
    }
    while True:
        raw = _ask("Source kind [url/file/directory]: ", default="url").casefold()
        if raw in choices:
            return choices[raw]
        typer.echo("Choose url, file, or directory.")


def _source_format() -> SourceFormat:
    while True:
        raw = _ask(
            "Format [auto/vless/vless_base64/xray_json/xray_json_array]: ",
            default="auto",
        ).casefold()
        try:
            return SourceFormat(raw)
        except ValueError:
            typer.echo("Unsupported format name.")


async def _source_wizard(
    paths: Paths,
    *,
    target_set_ids: list[str],
    egress_assertion_ids: list[str] | None = None,
) -> SourceDraft:
    source_id = _ask("Source ID: ", default=new_source_id())
    name = _ask("Display name: ", default="Imported source")
    kind = _source_kind()
    if kind is SourceKind.HTTP:
        location = _ask("Subscription URL (hidden): ", secret=True)
    elif kind is SourceKind.FILE:
        location = _ask("Source file path: ")
    else:
        location = _ask("Source directory path: ")
    if not location:
        raise ServiceError("source location is required")
    allow_insecure = False
    if kind is SourceKind.HTTP and location.casefold().startswith("http://"):
        allow_insecure = _confirm(
            "This source uses plain HTTP. Allow it explicitly?", default=False
        )
    headers: dict[str, str] = {}
    if kind is SourceKind.HTTP and _confirm("Add an authentication header?", default=False):
        while True:
            header_name = _ask("Header name: ", default="Authorization")
            header_value = _ask("Header value (hidden): ", secret=True)
            if not header_name or not header_value:
                raise ServiceError("both header name and value are required")
            headers[header_name] = header_value
            if not _confirm("Add another authentication header?", default=False):
                break
    source = SourceConfig(
        source_id=source_id,
        name=name,
        kind=kind,
        location=location,
        format=_source_format(),
        refresh_interval=_ask_float("Refresh interval, seconds: ", 300),
        timeout=_ask_float("Source timeout, seconds: ", 30),
        tags={
            item.strip()
            for item in _ask(
                "Source tags (comma-separated, optional): ", default=""
            ).split(",")
            if item.strip()
        },
        allow_empty=_confirm("Accept an empty source and remove its entries?", default=False),
        allow_insecure_http=allow_insecure,
        target_set_ids=target_set_ids,
        egress_assertion_ids=egress_assertion_ids or [],
        headers=headers,
    )
    candidates = await fetch_source_candidates(
        source, SourceLoader(base_dir=paths.config_path.parent)
    )
    typer.echo(f"Found {len(candidates)} entries (secret values are hidden):")
    for index, candidate in enumerate(candidates, 1):
        compatibility = candidate.compatibility.value
        typer.echo(f"  {index}. {candidate.safe_display} [{candidate.mode.value}; {compatibility}]")
    if not candidates and not source.allow_empty:
        raise ServiceError("empty source rejected by allow_empty policy")
    return SourceDraft(source, candidates, location, headers)


def _prepare_source_secrets(
    paths: Paths, draft: SourceDraft
) -> tuple[SourceConfig, dict[str, str]]:
    source = draft.source
    value = source.model_dump(mode="python")
    secrets: dict[str, str] = {}
    if source.kind is SourceKind.HTTP:
        transaction = uuid.uuid4().hex
        location_name = f"{source.source_id}-{transaction}-location"
        location_path = paths.data_dir / "secrets" / location_name
        location_ref = os.path.relpath(location_path, paths.config_path.parent)
        secrets[location_name] = draft.location_value
        value["location"] = None
        value["location_ref"] = {"file": location_ref}
        value["headers"] = {}
        value["headers_ref"] = {}
        for index, (name, secret) in enumerate(draft.header_values.items(), 1):
            filename = f"{source.source_id}-{transaction}-header-{index}"
            secret_path = paths.data_dir / "secrets" / filename
            secret_ref = os.path.relpath(secret_path, paths.config_path.parent)
            secrets[filename] = secret
            value["headers_ref"][name] = {"file": secret_ref}
    return SourceConfig.model_validate(value), secrets


def _default_target_set() -> TargetSetConfig:
    return TargetSetConfig(
        target_set_id="internet-default",
        name="Editable HTTPS reachability preset",
        quorum=2,
        targets=[
            TargetConfig(
                target_id="example-com",
                name="Example Domain",
                url="https://example.com/",
                expected_statuses={200},
            ),
            TargetConfig(
                target_id="gstatic-204",
                name="Google connectivity response",
                url="https://www.gstatic.com/generate_204",
                expected_statuses={204},
                max_body_bytes=1024,
            ),
            TargetConfig(
                target_id="cloudflare-trace",
                name="Cloudflare trace",
                url="https://www.cloudflare.com/cdn-cgi/trace",
                expected_statuses={200},
            ),
        ],
    )


def _custom_targets(existing: TargetSetConfig | None = None) -> TargetSetConfig:
    target_set_id = (
        existing.target_set_id
        if existing
        else _ask("Target set ID: ", default=new_target_set_id())
    )
    name = _ask("Target set name: ", default=existing.name if existing else "Reachability")
    previous_urls = ", ".join(item.url for item in existing.targets) if existing else ""
    typer.echo("Enter HTTP(S) target URLs separated by commas.")
    raw_urls = _ask(
        "URLs (blank keeps current values): ",
        default=previous_urls,
    )
    urls = [item.strip() for item in raw_urls.split(",") if item.strip()]
    if not urls:
        raise ServiceError("at least one target URL is required")
    existing_by_url = {item.url: item for item in existing.targets} if existing else {}
    targets: list[TargetConfig] = []
    for index, url in enumerate(urls, 1):
        old = existing_by_url.get(url)
        if old is not None and _confirm(
            f"Keep all existing settings for target {index} ({old.name})?", default=True
        ):
            targets.append(old)
            continue
        display_name = _ask(
            f"Name for target {index}: ",
            default=old.name if old else f"Target {index}",
        )
        status_default = (
            ",".join(str(item) for item in sorted(old.expected_statuses))
            if old
            else "200"
        )
        statuses_raw = _ask(
            f"Expected HTTP statuses for target {index}: ", default=status_default
        )
        try:
            statuses = {int(item.strip()) for item in statuses_raw.split(",") if item.strip()}
        except ValueError as exc:
            raise ServiceError("expected statuses must be comma-separated integers") from exc
        timeout_raw = _ask(
            f"Timeout seconds for target {index} (blank uses scheduler): ",
            default=str(old.timeout) if old and old.timeout is not None else "",
        )
        try:
            timeout = float(timeout_raw) if timeout_raw else None
        except ValueError as exc:
            raise ServiceError("target timeout must be a number") from exc
        matcher_default = old.body.kind.value if old and old.body else "none"
        matcher_kind = _ask(
            f"Body matcher for target {index} [none/exact/regex]: ",
            default=matcher_default,
        ).casefold()
        matcher = None
        if matcher_kind in {"exact", "regex"}:
            matcher = BodyMatcher(
                kind=matcher_kind,
                value=_ask(
                    f"Body {matcher_kind} value for target {index}: ",
                    default=old.body.value if old and old.body else "",
                ),
            )
        elif matcher_kind != "none":
            raise ServiceError("body matcher must be none, exact, or regex")
        max_body = _ask_int(
            f"Maximum response body bytes for target {index}: ",
            old.max_body_bytes if old else 64 * 1024,
        )
        follow_redirects = _confirm(
            f"Follow redirects for target {index}?",
            default=old.follow_redirects if old else False,
        )
        max_redirects = (
            _ask_int(
                f"Maximum redirects for target {index}: ",
                old.max_redirects if old and old.max_redirects else 5,
                maximum=20,
            )
            if follow_redirects
            else 0
        )
        enabled = _confirm(
            f"Enable target {index}?", default=old.enabled if old else True
        )
        targets.append(
            TargetConfig(
                target_id=old.target_id if old else new_target_id(),
                name=display_name,
                url=url,
                expected_statuses=statuses,
                timeout=timeout,
                body=matcher,
                max_body_bytes=max_body,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                enabled=enabled,
            )
        )
    quorum = _ask_int(
        "Quorum: ", existing.quorum if existing else min(2, len(targets)), maximum=len(targets)
    )
    return TargetSetConfig(
        target_set_id=target_set_id,
        name=name,
        targets=targets,
        quorum=quorum,
        enabled=existing.enabled if existing else True,
    )


def _target_set_wizard() -> TargetSetConfig:
    if _confirm("Use the editable three-target HTTPS preset?", default=True):
        preset = _default_target_set()
        typer.echo("Preset targets:")
        for target in preset.targets:
            typer.echo(f"  - {target.url} (HTTP {sorted(target.expected_statuses)})")
        if _confirm("Use these targets?", default=True):
            quorum = _ask_int("Quorum: ", preset.quorum, maximum=len(preset.targets))
            return preset.model_copy(update={"quorum": quorum})
    return _custom_targets()


def _egress_assertion_wizard(
    existing: EgressAssertionConfig | None = None,
) -> EgressAssertionConfig:
    assertion_id = (
        existing.assertion_id
        if existing is not None
        else _ask("Egress assertion ID: ", default=f"egress_{uuid.uuid4().hex}")
    )
    name = _ask(
        "Egress assertion name: ",
        default=existing.name if existing is not None else "Expected egress IP",
    )
    url = _ask(
        "Echo endpoint URL: ",
        default=existing.url if existing is not None else "https://api.ipify.org",
    )
    cidrs = _ask(
        "Expected CIDRs, comma-separated: ",
        default=(
            ",".join(existing.expected_cidrs) if existing is not None else ""
        ),
    )
    response_format = _ask(
        "Response format [plain/json]: ",
        default=(
            existing.response_format.value if existing is not None else "plain"
        ),
    ).casefold()
    if response_format not in {"plain", "json"}:
        raise ServiceError("egress response format must be plain or json")
    json_field = None
    if response_format == "json":
        json_field = _ask(
            "JSON field containing the IP (dot-separated): ",
            default=existing.json_field if existing and existing.json_field else "ip",
        )
    timeout_raw = _ask(
        "Egress timeout seconds (blank uses scheduler): ",
        default=(
            str(existing.timeout)
            if existing is not None and existing.timeout is not None
            else ""
        ),
    )
    try:
        timeout = float(timeout_raw) if timeout_raw else None
    except ValueError as exc:
        raise ServiceError("egress timeout must be a number") from exc
    return EgressAssertionConfig(
        assertion_id=assertion_id,
        name=name,
        url=url,
        expected_cidrs=[item.strip() for item in cidrs.split(",") if item.strip()],
        response_format=response_format,
        json_field=json_field,
        timeout=timeout,
        enabled=_confirm(
            "Enable this egress assertion?",
            default=existing.enabled if existing is not None else True,
        ),
    )


def _exclusion_rules(source_id: str, candidates: list[Any], selected: set[int]) -> list[AssignmentRule]:
    rules: list[AssignmentRule] = []
    used_names: set[str] = set()
    for index, candidate in enumerate(candidates):
        if candidate.compatibility is not Compatibility.SUPPORTED or index in selected:
            continue
        # Source candidates receive durable entry IDs only when the first
        # generation is accepted. An exact saved filter gives the wizard an
        # atomic pre-import exclusion and keeps excluding a future replacement
        # with the same user-facing identity.
        if candidate.name in used_names:
            continue
        used_names.add(candidate.name)
        rules.append(
            AssignmentRule(
                assignment_id=f"exclude_{source_id}_{len(rules) + 1}",
                source_id=source_id,
                filter=AssignmentFilter(name_regex=f"^{re.escape(candidate.name)}$"),
                enabled=False,
                target_set_ids=[],
            )
        )
    return rules


def _validate_unambiguous_name_selection(
    candidates: list[Any], selected: set[int]
) -> None:
    """Fail closed when an exact-name rule could affect a different candidate."""

    groups: dict[str, set[int]] = {}
    for index, candidate in enumerate(candidates):
        groups.setdefault(candidate.name, set()).add(index)
    for name, indices in groups.items():
        chosen = indices & selected
        if chosen and chosen != indices:
            raise ServiceError(
                "entries with duplicate display names cannot be selected independently "
                f"during import ({redact_text(name, max_length=80)}); import them "
                "together, then assign durable entry IDs"
            )


def _profile_selection_rules(
    source: SourceConfig,
    candidates: list[Any],
    selected: set[int],
) -> list[AssignmentRule]:
    """Collect choices that cannot be inferred from a complete profile."""

    rules: list[AssignmentRule] = []
    name_counts = {
        candidate.name: sum(item.name == candidate.name for item in candidates)
        for candidate in candidates
    }
    for index, candidate in enumerate(candidates):
        if index not in selected or candidate.mode.value != "profile":
            continue
        profile = candidate.profile or candidate.payload
        if not isinstance(profile, dict):
            continue
        mode = "profile"
        outbound_tag: str | None = None
        inbound_tag: str | None = candidate.inbound_tag
        typer.echo(f"Profile choice for {candidate.safe_display}:")
        if _confirm("  Probe a specific VLESS outbound instead of full routing?", default=False):
            mode = "connection"
            outbounds = [
                item
                for item in profile.get("outbounds", [])
                if isinstance(item, dict) and item.get("protocol") == "vless"
            ]
            if len(outbounds) > 1:
                tagged = [str(item.get("tag")) for item in outbounds if item.get("tag")]
                if len(tagged) != len(outbounds):
                    raise ServiceError("multiple VLESS outbounds require tags for explicit selection")
                for number, tag in enumerate(tagged, 1):
                    typer.echo(f"    {number}. {redact_text(tag, max_length=80)}")
                chosen = _select_indices("  Select one outbound: ", len(tagged), default_all=False)
                if len(chosen) != 1:
                    raise ServiceError("select exactly one outbound")
                outbound_tag = tagged[next(iter(chosen))]
            elif outbounds:
                tag = outbounds[0].get("tag")
                outbound_tag = str(tag) if tag else None
        else:
            compatible = [
                item
                for item in profile.get("inbounds", [])
                if isinstance(item, dict) and item.get("protocol") in {"socks", "http"}
            ]
            if len(compatible) > 1:
                tags = [str(item.get("tag")) for item in compatible]
                typer.echo("  Select the client inbound to model:")
                for number, tag in enumerate(tags, 1):
                    typer.echo(f"    {number}. {redact_text(tag, max_length=80)}")
                chosen = _select_indices("  Select one inbound: ", len(tags), default_all=False)
                if len(chosen) != 1:
                    raise ServiceError("select exactly one inbound")
                inbound_tag = tags[next(iter(chosen))]
        if mode != candidate.mode.value or outbound_tag or inbound_tag != candidate.inbound_tag:
            if name_counts[candidate.name] > 1:
                raise ServiceError(
                    "profile choices for duplicate display names require durable entry IDs"
                )
            rules.append(
                AssignmentRule(
                    assignment_id=f"profile_{source.source_id}_{len(rules) + 1}",
                    source_id=source.source_id,
                    filter=AssignmentFilter(name_regex=f"^{re.escape(candidate.name)}$"),
                    enabled=True,
                    target_set_ids=list(source.target_set_ids),
                    mode=mode,
                    outbound_tag=outbound_tag,
                    inbound_tag=inbound_tag,
                    egress_assertion_ids=list(source.egress_assertion_ids),
                )
            )
    return rules


def _configuration_summary(config: AppConfig, draft: SourceDraft) -> None:
    supported = sum(
        item.compatibility is Compatibility.SUPPORTED for item in draft.candidates
    )
    typer.echo("\nSummary:")
    typer.echo(f"  instance_id: {config.instance_id}")
    typer.echo(f"  source_id: {draft.source.source_id}")
    typer.echo(f"  entries: {len(draft.candidates)} ({supported} supported)")
    typer.echo(f"  target sets: {', '.join(draft.source.target_set_ids)}")
    typer.echo(f"  interval: {config.scheduler.interval}s")
    typer.echo(f"  request timeout: {config.scheduler.request_timeout}s")
    typer.echo(f"  active runtimes: {config.scheduler.max_active_runtimes}")
    typer.echo(f"  parallel requests: {config.scheduler.max_parallel_requests}")
    typer.echo(f"  egress assertions: {len(config.egress_assertions)}")
    typer.echo("  default modes: VLESS URI=connection, full JSON=profile")


@app.command()
def setup(
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Persistent data directory."),
    config_path: Path | None = typer.Option(None, "--config", help="Configuration path."),
    xray_binary: str | None = typer.Option(None, "--xray-binary", help="Xray executable."),
) -> None:
    """Interactively create the first source, targets, and scheduler settings."""

    paths = _paths(data_dir, config_path, xray_binary)
    try:
        previous: AppConfig | None = None
        expected_revision = "__absent__"
        if paths.config_path.exists():
            previous, expected_revision = _run(_config_for_edit(paths))
        if previous is not None and not _confirm(
            "Configuration already exists. Replace it?", default=False
        ):
            raise typer.Abort()
        instance_default = previous.instance_id if previous else "prober-1"
        instance_id = _ask("Instance ID: ", default=instance_default)
        target_set = _target_set_wizard()
        egress_assertions: list[EgressAssertionConfig] = []
        if _confirm("Configure an optional egress IP assertion?", default=False):
            egress_assertions.append(_egress_assertion_wizard())
        draft = _run(
            _source_wizard(
                paths,
                target_set_ids=[target_set.target_set_id],
                egress_assertion_ids=[
                    item.assertion_id for item in egress_assertions if item.enabled
                ],
            )
        )
        supported_indices = {
            index
            for index, candidate in enumerate(draft.candidates)
            if candidate.compatibility is Compatibility.SUPPORTED
        }
        selected = _select_indices(
            "Entries to enable [all or comma-separated numbers]: ",
            len(draft.candidates),
            default_all=True,
        ) & supported_indices
        _validate_unambiguous_name_selection(draft.candidates, selected)
        scheduler = SchedulerConfig(
            interval=_ask_float("Check interval, seconds: ", 60),
            request_timeout=_ask_float("Request timeout, seconds: ", 15),
            runtime_start_timeout=_ask_float("Xray startup timeout, seconds: ", 10),
            max_active_runtimes=_ask_int("Maximum active Xray runtimes: ", 8),
            max_parallel_requests=_ask_int("Maximum parallel HTTP requests: ", 32),
            max_queue_size=_ask_int("Maximum scheduler queue: ", 1024),
            max_result_age=_ask_float("Maximum result age, seconds: ", 180),
        )
        config = AppConfig(
            instance_id=instance_id,
            sources=[draft.source],
            target_sets=[target_set],
            egress_assertions=egress_assertions,
            assignments=[
                *_profile_selection_rules(draft.source, draft.candidates, selected),
                *_exclusion_rules(draft.source.source_id, draft.candidates, selected),
            ],
            scheduler=scheduler,
        )
        _configuration_summary(config, draft)
        if not _confirm("Save and accept this configuration?", default=True):
            raise typer.Abort()
        persisted_source, secrets = _prepare_source_secrets(paths, draft)
        config = config.model_copy(update={"sources": [persisted_source]})

        async def apply_and_refresh() -> Any:
            await _apply_config(
                paths,
                config,
                expected_revision=expected_revision,
                secrets=secrets,
            )
            return await _control_or_service(
                paths, "refresh", {"source_id": persisted_source.source_id}
            )

        result = _run(apply_and_refresh())
        _emit({"saved": str(paths.config_path), "refresh": result}, json_output=False)
        if any(item.get("refresh_success") is False for item in result):
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@app.command()
def serve(
    data_dir: Path | None = typer.Option(None, "--data-dir", help="Persistent data directory."),
    config_path: Path | None = typer.Option(None, "--config", help="Configuration path."),
    xray_binary: str | None = typer.Option(None, "--xray-binary", help="Xray executable."),
    host: str | None = typer.Option(None, "--host", help="HTTP bind address."),
    port: int | None = typer.Option(None, "--port", min=1, max=65535, help="HTTP port."),
    log_level: str = typer.Option("info", "--log-level", help="Logging level."),
) -> None:
    """Run one Uvicorn worker with the managed prober lifespan."""

    paths = _paths(data_dir, config_path, xray_binary)
    configured = _load_existing(paths, required=False)
    bind_host = host or (configured.api.host if configured else "127.0.0.1")
    bind_port = port or (configured.api.port if configured else 8080)
    configure_logging(log_level)
    service = ProberService(
        paths.data_dir,
        config_path=paths.config_path,
        xray_binary=paths.xray_binary,
        schedule_enabled=True,
        control_enabled=True,
    )
    api = create_app(service)
    uvicorn.run(
        api,
        host=bind_host,
        port=bind_port,
        workers=1,
        reload=False,
        log_config=None,
        access_log=False,
    )


@subscription_app.command("add")
def subscription_add(
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
    xray_binary: str | None = typer.Option(None, "--xray-binary"),
) -> None:
    """Interactively add and validate an HTTP, file, or directory source."""

    paths = _paths(data_dir, config_path, xray_binary)
    try:
        config, expected_revision = _run(_config_for_edit(paths))
        if not config.target_sets:
            target_set = _target_set_wizard()
            target_sets = [target_set]
            selected_set_ids = [target_set.target_set_id]
        else:
            typer.echo("Target sets:")
            for index, item in enumerate(config.target_sets, 1):
                typer.echo(f"  {index}. {item.name} [{item.target_set_id}]")
            chosen = _select_indices(
                "Target sets for this source: ", len(config.target_sets), default_all=True
            )
            selected_set_ids = [
                item.target_set_id
                for index, item in enumerate(config.target_sets)
                if index in chosen
            ]
            target_sets = list(config.target_sets)
        selected_egress_ids: list[str] = []
        if config.egress_assertions:
            typer.echo("Egress assertions:")
            for index, item in enumerate(config.egress_assertions, 1):
                typer.echo(f"  {index}. {item.name} [{item.assertion_id}]")
            selected_egress = _select_indices(
                "Egress assertions for this source: ",
                len(config.egress_assertions),
                default_all=False,
            )
            selected_egress_ids = [
                item.assertion_id
                for index, item in enumerate(config.egress_assertions)
                if index in selected_egress
            ]
        draft = _run(
            _source_wizard(
                paths,
                target_set_ids=selected_set_ids,
                egress_assertion_ids=selected_egress_ids,
            )
        )
        if any(item.source_id == draft.source.source_id for item in config.sources):
            raise ServiceError("source ID already exists")
        supported = {
            index
            for index, candidate in enumerate(draft.candidates)
            if candidate.compatibility is Compatibility.SUPPORTED
        }
        selected = _select_indices(
            "Entries to enable [all or comma-separated numbers]: ",
            len(draft.candidates),
            default_all=True,
        ) & supported
        _validate_unambiguous_name_selection(draft.candidates, selected)
        if not _confirm("Add this source?", default=True):
            raise typer.Abort()
        persisted, secrets = _prepare_source_secrets(paths, draft)
        updated = config.model_copy(
            update={
                "sources": [*config.sources, persisted],
                "target_sets": target_sets,
                "assignments": [
                    *config.assignments,
                    *_profile_selection_rules(draft.source, draft.candidates, selected),
                    *_exclusion_rules(persisted.source_id, draft.candidates, selected),
                ],
            }
        )

        async def apply_and_refresh() -> Any:
            await _apply_config(
                paths,
                AppConfig.model_validate(updated),
                expected_revision=expected_revision,
                secrets=secrets,
            )
            return await _control_or_service(paths, "refresh", {"source_id": persisted.source_id})

        result = _run(apply_and_refresh())
        _emit(result, json_output=False)
        if any(item.get("refresh_success") is False for item in result):
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@subscription_app.command("list")
def subscription_list(
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """List configured sources and their last refresh state without locations."""

    paths = _paths(data_dir, config_path)
    try:
        config = _load_existing(paths)
        status = _run(_control_or_service(paths, "status"))
        states = {item["source_id"]: item for item in status.get("sources", [])}
        rows = []
        assert config is not None
        for source in config.sources:
            state = states.get(source.source_id, {})
            rows.append(
                {
                    "source_id": source.source_id,
                    "name": source.name,
                    "kind": source.kind.value,
                    "format": source.format.value,
                    "enabled": source.enabled,
                    "refresh_success": state.get("refresh_success"),
                    "last_success_timestamp": state.get("last_success_timestamp", 0),
                    "reason": state.get("reason"),
                }
            )
        _emit(rows, json_output=json_output)
    except Exception as exc:
        _fail(exc)


@subscription_app.command("refresh")
def subscription_refresh(
    source_id: str | None = typer.Argument(None),
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
    xray_binary: str | None = typer.Option(None, "--xray-binary"),
) -> None:
    """Refresh one source, or all sources when no ID is supplied."""

    paths = _paths(data_dir, config_path, xray_binary)
    try:
        result = _run(_control_or_service(paths, "refresh", {"source_id": source_id}))
        _emit(result, json_output=json_output)
        if any(item.get("refresh_success") is False for item in result):
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(exc)


@subscription_app.command("remove")
def subscription_remove(
    source_id: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Remove a source after displaying affected checks; retain its LKG backup."""

    paths = _paths(data_dir, config_path)
    try:
        config, expected_revision = _run(_config_for_edit(paths))
        if source_id not in {item.source_id for item in config.sources}:
            raise ServiceError("source not found")
        checks = _run(_control_or_service(paths, "checks"))
        affected = [item["check_id"] for item in checks if item.get("source_id") == source_id]
        typer.echo(f"Affected checks ({len(affected)}):")
        for check_id in affected:
            typer.echo(f"  - {check_id}")
        if not yes and not _confirm(
            "Remove the source? Its private last-known-good copy is retained for backup.",
            default=False,
        ):
            raise typer.Abort()
        updated = config.model_copy(
            update={
                "sources": [item for item in config.sources if item.source_id != source_id],
                "assignments": [
                    item for item in config.assignments if item.source_id != source_id
                ],
            }
        )
        _run(
            _apply_config(
                paths,
                AppConfig.model_validate(updated),
                expected_revision=expected_revision,
            )
        )
        typer.echo(f"Removed source {source_id}; LKG files were not deleted.")
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@entries_app.command("list")
def entries_list(
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """List safe entry metadata, compatibility, and assigned check IDs."""

    paths = _paths(data_dir, config_path)
    try:
        result = _run(_control_or_service(paths, "entries"))
        _emit(result, json_output=json_output)
    except Exception as exc:
        _fail(exc)


@entries_app.command("reconcile")
def entries_reconcile(
    source_id: str | None = typer.Argument(None),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Resolve ambiguous source identity mappings interactively."""

    paths = _paths(data_dir, config_path)
    try:
        config, _revision = _run(_config_for_edit(paths))
        if source_id is None:
            typer.echo("Sources:")
            for index, source in enumerate(config.sources, 1):
                typer.echo(f"  {index}. {source.name} [{source.source_id}]")
            selected = _select_indices("Select one source: ", len(config.sources), default_all=False)
            if len(selected) != 1:
                raise ServiceError("select exactly one source")
            source_id = config.sources[next(iter(selected))].source_id
        preview = _run(
            _control_or_service(paths, "preview_reconciliation", {"source_id": source_id})
        )
        conflicts = preview.get("conflicts", [])
        if not conflicts:
            typer.echo("No ambiguous identity mappings were found.")
            return
        mapping = dict(preview.get("assignments", {}))
        candidates = {item["candidate_id"]: item for item in preview.get("candidates", [])}
        used = set(mapping.values())
        for conflict in conflicts:
            typer.echo(conflict["message"])
            options = list(conflict.get("possible_entry_ids", []))
            for candidate_id in conflict.get("candidate_ids", []):
                candidate = candidates.get(candidate_id, {})
                typer.echo(f"  {candidate_id}: {candidate.get('safe_display', 'entry')}")
                typer.echo("  Existing IDs: " + (", ".join(options) or "(none; enter 'new')"))
                while True:
                    chosen = _ask("  Map to entry ID or 'new': ", default="new")
                    if chosen.casefold() == "new":
                        from .identity import new_entry_id

                        chosen = new_entry_id()
                    if chosen in used:
                        typer.echo("That entry ID is already assigned in this candidate generation.")
                        continue
                    if options and chosen not in options and not chosen.startswith("entry_"):
                        typer.echo("Choose a listed ID or 'new'.")
                        continue
                    mapping[candidate_id] = chosen
                    used.add(chosen)
                    break
        if not _confirm("Apply this complete mapping and accept the new generation?", default=False):
            raise typer.Abort()
        result = _run(
            _control_or_service(
                paths,
                "reconcile",
                {
                    "source_id": source_id,
                    "mapping": mapping,
                    "expected_revision": preview.get("revision"),
                },
            )
        )
        _emit(result, json_output=False)
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@targets_app.command("edit")
def targets_edit(
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Create, replace, or remove a target set through a guided editor."""

    paths = _paths(data_dir, config_path)
    try:
        config, expected_revision = _run(_config_for_edit(paths))
        typer.echo("Target sets:")
        for index, item in enumerate(config.target_sets, 1):
            typer.echo(f"  {index}. {item.name} [{item.target_set_id}], quorum={item.quorum}")
        action = _ask("Action [create/edit/remove]: ", default="create").casefold()
        target_sets = list(config.target_sets)
        if action == "create":
            target_sets.append(_target_set_wizard())
        elif action in {"edit", "remove"}:
            selected = _select_indices("Select one target set: ", len(target_sets), default_all=False)
            if len(selected) != 1:
                raise ServiceError("select exactly one target set")
            index = next(iter(selected))
            current = target_sets[index]
            if action == "edit":
                target_sets[index] = _custom_targets(current)
            else:
                affected_sources = [
                    item.source_id
                    for item in config.sources
                    if current.target_set_id in item.target_set_ids
                ]
                typer.echo("Affected sources: " + (", ".join(affected_sources) or "(none)"))
                if not _confirm("Remove this target set and all references?", default=False):
                    raise typer.Abort()
                target_sets.pop(index)
                config = config.model_copy(
                    update={
                        "sources": [
                            source.model_copy(
                                update={
                                    "target_set_ids": [
                                        item
                                        for item in source.target_set_ids
                                        if item != current.target_set_id
                                    ]
                                }
                            )
                            for source in config.sources
                        ],
                        "assignments": [
                            rule.model_copy(
                                update={
                                    "target_set_ids": [
                                        item
                                        for item in rule.target_set_ids
                                        if item != current.target_set_id
                                    ]
                                }
                            )
                            for rule in config.assignments
                        ],
                        "default_target_set_ids": [
                            item
                            for item in config.default_target_set_ids
                            if item != current.target_set_id
                        ],
                    }
                )
        else:
            raise ServiceError("action must be create, edit, or remove")
        updated = config.model_copy(update={"target_sets": target_sets})
        _run(
            _apply_config(
                paths,
                AppConfig.model_validate(updated),
                expected_revision=expected_revision,
            )
        )
        typer.echo("Target sets updated.")
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@assignments_app.command("edit")
def assignments_edit(
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Add/remove ordered source, entry, or saved-filter assignment rules."""

    paths = _paths(data_dir, config_path)
    try:
        config, expected_revision = _run(_config_for_edit(paths))
        typer.echo("Assignments (first matching saved rule wins):")
        for index, rule in enumerate(config.assignments, 1):
            typer.echo(
                f"  {index}. {rule.assignment_id}: enabled={rule.enabled}, "
                f"sets={','.join(rule.target_set_ids) or '-'}"
            )
        action = _ask("Action [add/remove]: ", default="add").casefold()
        rules = list(config.assignments)
        if action == "remove":
            selected = _select_indices("Rules to remove: ", len(rules), default_all=False)
            rules = [item for index, item in enumerate(rules) if index not in selected]
        elif action == "add":
            assignment_id = _ask("Assignment ID: ", default=f"rule-{len(rules) + 1}")
            selector = _ask("Selector [source/entry/filter]: ", default="filter").casefold()
            source_id: str | None = None
            entry_id: str | None = None
            filter_value: AssignmentFilter | None = None
            if selector == "source":
                source_id = _ask("Source ID: ")
            elif selector == "entry":
                entry_id = _ask("Entry ID: ")
            elif selector == "filter":
                name_regex = _ask("Name regular expression (blank for any): ") or None
                protocol = _ask("Protocol (blank for any): ") or None
                transport = _ask("Transport (blank for any): ") or None
                tags = {
                    item.strip()
                    for item in _ask("Required tags, comma-separated: ").split(",")
                    if item.strip()
                }
                filter_value = AssignmentFilter(
                    name_regex=name_regex,
                    protocol=protocol,
                    transport=transport,
                    tags=tags,
                )
                if _confirm("Limit this filter to one source?", default=False):
                    source_id = _ask("Source ID: ")
            else:
                raise ServiceError("selector must be source, entry, or filter")
            enabled = _confirm("Enable matching entries?", default=True)
            typer.echo("Target sets:")
            for index, item in enumerate(config.target_sets, 1):
                typer.echo(f"  {index}. {item.name} [{item.target_set_id}]")
            selected_sets = _select_indices(
                "Assign target sets: ", len(config.target_sets), default_all=enabled
            )
            target_set_ids = [
                item.target_set_id
                for index, item in enumerate(config.target_sets)
                if index in selected_sets
            ]
            mode_raw = _ask("Override mode [blank/connection/profile]: ").casefold() or None
            outbound_tag = _ask(
                "Selected VLESS outbound tag (blank for automatic): "
            ) or None
            inbound_tag = _ask(
                "Profile inbound tag to model (blank for automatic): "
            ) or None
            lifecycle = _ask(
                "Runtime lifecycle [blank/fresh/persistent]: "
            ).casefold() or None
            if lifecycle not in {None, "fresh", "persistent"}:
                raise ServiceError("runtime lifecycle must be fresh or persistent")
            egress_ids: list[str] = []
            if config.egress_assertions:
                typer.echo("Egress assertions:")
                for index, item in enumerate(config.egress_assertions, 1):
                    typer.echo(f"  {index}. {item.name} [{item.assertion_id}]")
                selected_egress = _select_indices(
                    "Assign egress assertions: ",
                    len(config.egress_assertions),
                    default_all=False,
                )
                egress_ids = [
                    item.assertion_id
                    for index, item in enumerate(config.egress_assertions)
                    if index in selected_egress
                ]
            rules.append(
                AssignmentRule(
                    assignment_id=assignment_id,
                    source_id=source_id,
                    entry_id=entry_id,
                    filter=filter_value,
                    enabled=enabled,
                    target_set_ids=target_set_ids,
                    mode=mode_raw,
                    runtime_lifecycle=lifecycle,
                    outbound_tag=outbound_tag,
                    inbound_tag=inbound_tag,
                    egress_assertion_ids=egress_ids,
                )
            )
        else:
            raise ServiceError("action must be add or remove")
        updated = config.model_copy(update={"assignments": rules})
        _run(
            _apply_config(
                paths,
                AppConfig.model_validate(updated),
                expected_revision=expected_revision,
            )
        )
        typer.echo("Assignments updated.")
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@egress_app.command("edit")
def egress_edit(
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Create, replace, or remove an egress assertion through a guided editor."""

    paths = _paths(data_dir, config_path)
    try:
        config, expected_revision = _run(_config_for_edit(paths))
        typer.echo("Egress assertions:")
        for index, item in enumerate(config.egress_assertions, 1):
            typer.echo(
                f"  {index}. {item.name} [{item.assertion_id}], enabled={item.enabled}"
            )
        action = _ask("Action [create/edit/remove]: ", default="create").casefold()
        assertions = list(config.egress_assertions)
        assignments = list(config.assignments)
        sources = list(config.sources)
        if action == "create":
            assertions.append(_egress_assertion_wizard())
        elif action in {"edit", "remove"}:
            if not assertions:
                raise ServiceError("there are no egress assertions to edit")
            selected = _select_indices(
                "Select one egress assertion: ", len(assertions), default_all=False
            )
            if len(selected) != 1:
                raise ServiceError("select exactly one egress assertion")
            index = next(iter(selected))
            current = assertions[index]
            if action == "edit":
                assertions[index] = _egress_assertion_wizard(current)
            else:
                affected = [
                    item.assignment_id
                    for item in assignments
                    if current.assertion_id in item.egress_assertion_ids
                ]
                typer.echo(
                    "Affected assignments: " + (", ".join(affected) or "(none)")
                )
                if not _confirm(
                    "Remove this assertion and all source/assignment references?",
                    default=False,
                ):
                    raise typer.Abort()
                assertions.pop(index)
                sources = [
                    source.model_copy(
                        update={
                            "egress_assertion_ids": [
                                item
                                for item in source.egress_assertion_ids
                                if item != current.assertion_id
                            ]
                        }
                    )
                    for source in sources
                ]
                assignments = [
                    rule.model_copy(
                        update={
                            "egress_assertion_ids": [
                                item
                                for item in rule.egress_assertion_ids
                                if item != current.assertion_id
                            ]
                        }
                    )
                    for rule in assignments
                ]
        else:
            raise ServiceError("action must be create, edit, or remove")
        updated = config.model_copy(
            update={
                "sources": sources,
                "assignments": assignments,
                "egress_assertions": assertions,
            }
        )
        _run(
            _apply_config(
                paths,
                AppConfig.model_validate(updated),
                expected_revision=expected_revision,
            )
        )
        typer.echo("Egress assertions updated.")
    except typer.Abort:
        raise
    except Exception as exc:
        _fail(exc)


@check_app.command("run")
def check_run(
    check_id: str | None = typer.Argument(None),
    once: bool = typer.Option(True, "--once/--no-once", help="Run exactly one cycle."),
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
    xray_binary: str | None = typer.Option(None, "--xray-binary"),
) -> None:
    """Run one cycle for a selected check, or all enabled checks."""

    if not once:
        _fail("scheduled execution belongs to 'prober serve'; --once is required")
    paths = _paths(data_dir, config_path, xray_binary)
    try:
        response = _run(_control_or_service(paths, "run", {"check_id": check_id}))
        _emit(response.get("results", []), json_output=json_output)
        raise typer.Exit(code=int(response.get("exit_code", 2)))
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(exc)


@app.command()
def status(
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Show daemon/standalone state and latest current-generation results."""

    paths = _paths(data_dir, config_path)
    try:
        result = _run(_control_or_service(paths, "status"))
        _emit(result, json_output=json_output)
    except Exception as exc:
        _fail(exc)


@config_app.command("validate")
def config_validate(
    path: Path | None = typer.Argument(None),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Validate YAML without applying it or contacting targets."""

    paths = _paths(data_dir, config_path)
    candidate = path.resolve() if path else paths.config_path
    try:
        config = load_config(candidate)
        _emit(
            {
                "valid": True,
                "path": str(candidate),
                "schema_version": config.schema_version,
                "instance_id": config.instance_id,
                "sources": len(config.sources),
                "target_sets": len(config.target_sets),
            },
            json_output=json_output,
        )
    except Exception as exc:
        _fail(exc)


@config_app.command("export")
def config_export(
    output: Path | None = typer.Option(None, "--output", "-o"),
    json_output: bool = typer.Option(False, "--json"),
    data_dir: Path | None = typer.Option(None, "--data-dir"),
    config_path: Path | None = typer.Option(None, "--config"),
) -> None:
    """Export a secret-free portable bundle with stable ID mappings."""

    paths = _paths(data_dir, config_path)
    try:
        config = _load_existing(paths)
        assert config is not None
        store = DataStore(paths.data_dir)
        generations = {}
        entries_by_source = {}
        for source in config.sources:
            generation = store.load_lkg(source.source_id)
            if generation is None:
                continue
            generations[source.source_id] = generation
            entries_by_source[source.source_id] = {
                entry.entry_id: entry for entry in generation.entries
            }

        # Recompute every exported digest from the current LKG using a strict
        # semantic allow-list. Never trust a persisted value here: a malformed
        # registry could otherwise turn export into a credential-hash oracle.
        persisted = store.load_identity_registry()
        registry_sources: dict[str, list[dict[str, Any]]] = {}
        for source in config.sources:
            current_entries = entries_by_source.get(source.source_id, {})
            safe_bindings: list[dict[str, Any]] = []
            seen: set[str] = set()
            for binding in persisted.sources.get(source.source_id, []):
                item: dict[str, Any] = {
                    "entry_id": binding.entry_id,
                    "active": binding.active,
                }
                current = current_entries.get(binding.entry_id)
                fingerprint = (
                    safe_reconciliation_fingerprint(current)
                    if current is not None
                    else None
                )
                if fingerprint is not None:
                    item["connection_fingerprint"] = fingerprint
                safe_bindings.append(item)
                seen.add(binding.entry_id)
            for entry_id, entry in current_entries.items():
                if entry_id in seen:
                    continue
                item = {"entry_id": entry_id, "active": True}
                fingerprint = safe_reconciliation_fingerprint(entry)
                if fingerprint is not None:
                    item["connection_fingerprint"] = fingerprint
                safe_bindings.append(item)
            registry_sources[source.source_id] = sorted(
                safe_bindings, key=lambda item: str(item["entry_id"])
            )

        inventory = compile_inventory(config, generations)
        expected_checks = [
            {
                "check_id": item.definition.check_id,
                "entry_id": item.definition.entry_id,
                "source_id": item.definition.source_id,
                "mode": item.definition.mode.value,
                "target_set_id": item.definition.target_set_id,
                "enabled": item.definition.enabled,
            }
            for item in sorted(
                inventory.values(), key=lambda item: item.definition.check_id
            )
        ]
        bundle = {
            "export_version": 2,
            "config": export_config_dict(config),
            "identity_registry": {
                "schema_version": config.schema_version,
                "sources": registry_sources,
            },
            "expected_inventory": {
                "instance_id": config.instance_id,
                "sources": [
                    {"source_id": source.source_id, "enabled": source.enabled}
                    for source in config.sources
                ],
                "checks": expected_checks,
            },
        }
        text = (
            json.dumps(bundle, ensure_ascii=False, indent=2)
            if json_output
            else yaml.safe_dump(bundle, allow_unicode=True, sort_keys=False)
        )
        if output is not None:
            atomic_write_text(
                output,
                text + ("" if text.endswith("\n") else "\n"),
                mode=0o600,
            )
            typer.echo(str(output))
        else:
            typer.echo(text, nl=not text.endswith("\n"))
    except Exception as exc:
        _fail(exc)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
