"""Deterministic assignment precedence shared by setup, refresh and daemon."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from .safe_regex import safe_name_regex_search


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _text(value: Any) -> str:
    return str(getattr(value, "value", value))


@dataclass(frozen=True, slots=True)
class AssignmentDecision:
    enabled: bool
    target_set_ids: tuple[str, ...]
    rule: str
    mode: str
    runtime_lifecycle: str | None = None
    outbound_tag: str | None = None
    inbound_tag: str | None = None
    # Durable public selector identity. This is an assignment ID, never a raw
    # profile tag, and is safe to feed into public check-ID derivation.
    selection_id: str | None = None
    egress_assertion_ids: tuple[str, ...] = ()


def matches_filter(entry: Any, selector: Any) -> bool:
    if not selector:
        return True
    name = str(_get(entry, "name", ""))
    name_glob = _get(selector, "name_glob")
    if name_glob and not fnmatch.fnmatchcase(name.casefold(), str(name_glob).casefold()):
        return False
    name_regex = _get(selector, "name_regex")
    if name_regex and not safe_name_regex_search(str(name_regex), name):
        return False
    for field in ("protocol", "transport", "source_id", "mode"):
        expected = _get(selector, field)
        if expected is not None and _text(_get(entry, field, "")) != _text(expected):
            return False
    required_tags = set(_get(selector, "tags", ()) or ())
    if not required_tags.issubset(set(_get(entry, "tags", ()) or ())):
        return False
    return True


def resolve_assignment(
    entry: Any,
    *,
    rules: list[Any],
    source_target_set_ids: list[str] | tuple[str, ...] = (),
    source_egress_assertion_ids: list[str] | tuple[str, ...] = (),
    global_target_set_ids: list[str] | tuple[str, ...] = (),
    source_enabled: bool = True,
) -> AssignmentDecision:
    entry_id = _text(_get(entry, "entry_id"))

    # Explicit per-entry decisions always win, independent of list order.
    for rule in rules:
        explicit_id = _get(rule, "entry_id")
        explicit_ids = set(_get(rule, "entry_ids", ()) or ())
        if explicit_id == entry_id or entry_id in explicit_ids:
            rule_id = _get(rule, "assignment_id", _get(rule, "rule_id", entry_id))
            return _decision(entry, rule, f"entry:{rule_id}")

    # Saved rules are evaluated in their persisted order. A source selector may
    # be present alongside the filter and is part of matching.
    for index, rule in enumerate(rules):
        if _get(rule, "entry_id") or _get(rule, "entry_ids"):
            continue
        selector = _get(rule, "filter", _get(rule, "selector", None))
        source_id = _get(rule, "source_id")
        if source_id and _text(source_id) != _text(_get(entry, "source_id")):
            continue
        if matches_filter(entry, selector):
            rule_id = _get(rule, "assignment_id", _get(rule, "rule_id", index))
            return _decision(entry, rule, f"rule:{rule_id}")

    mode = _text(_get(entry, "mode", "connection"))
    if source_target_set_ids:
        return AssignmentDecision(
            enabled=source_enabled,
            target_set_ids=tuple(source_target_set_ids),
            rule="source-default",
            mode=mode,
            egress_assertion_ids=tuple(source_egress_assertion_ids),
        )
    return AssignmentDecision(
        enabled=source_enabled,
        target_set_ids=tuple(global_target_set_ids),
        rule="global-default",
        mode=mode,
        egress_assertion_ids=tuple(source_egress_assertion_ids),
    )


def _decision(entry: Any, rule: Any, name: str) -> AssignmentDecision:
    runtime_lifecycle = _get(rule, "runtime_lifecycle")
    assignment_id = _text(
        _get(rule, "assignment_id", _get(rule, "rule_id", name))
    )
    outbound_tag = _get(rule, "outbound_tag")
    inbound_tag = _get(rule, "inbound_tag")
    selection_id = _get(rule, "selection_id")
    if selection_id is None and (outbound_tag is not None or inbound_tag is not None):
        selection_id = assignment_id
    return AssignmentDecision(
        enabled=bool(_get(rule, "enabled", True)),
        target_set_ids=tuple(_get(rule, "target_set_ids", ()) or ()),
        rule=name,
        mode=_text(_get(rule, "mode", None) or _get(entry, "mode", "connection")),
        runtime_lifecycle=(
            _text(runtime_lifecycle) if runtime_lifecycle is not None else None
        ),
        outbound_tag=outbound_tag,
        inbound_tag=inbound_tag,
        selection_id=_text(selection_id) if selection_id is not None else None,
        egress_assertion_ids=tuple(_get(rule, "egress_assertion_ids", ()) or ()),
    )
