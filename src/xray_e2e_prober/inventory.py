"""Compile accepted source generations into the effective check inventory."""

from __future__ import annotations

from dataclasses import dataclass

from .assignments import AssignmentDecision, resolve_assignment
from .identity import stable_check_id
from .models import (
    AppConfig,
    CheckDefinition,
    CheckMode,
    Compatibility,
    EgressAssertionConfig,
    EntryRecord,
    SourceGeneration,
    TargetSetConfig,
)


class InventoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CompiledCheck:
    definition: CheckDefinition
    entry: EntryRecord
    target_set: TargetSetConfig
    egress_assertions: tuple[EgressAssertionConfig, ...]
    assignment_reason: str


def public_check_id(
    entry_id: str,
    target_set_id: str,
    mode: str,
    selection_id: str | None = None,
) -> str:
    return stable_check_id(entry_id, mode, target_set_id, selection_id)


def compile_inventory(
    config: AppConfig, generations: dict[str, SourceGeneration]
) -> dict[str, CompiledCheck]:
    target_sets = {item.target_set_id: item for item in config.target_sets}
    assertions = {item.assertion_id: item for item in config.egress_assertions}
    sources = {item.source_id: item for item in config.sources}
    compiled: dict[str, CompiledCheck] = {}

    for source_id, generation in generations.items():
        source = sources.get(source_id)
        if source is None:
            continue
        for entry in generation.entries:
            # Source tags are assignment metadata. Keep the immutable LKG entry
            # untouched while exposing the effective union consistently to
            # matching and read-only inventory snapshots.
            effective_entry = entry.model_copy(
                update={"tags": set(entry.tags) | set(source.tags)}
            )
            decision = resolve_assignment(
                effective_entry,
                rules=config.assignments,
                source_target_set_ids=source.target_set_ids,
                source_egress_assertion_ids=source.egress_assertion_ids,
                global_target_set_ids=config.default_target_set_ids,
                source_enabled=source.enabled and entry.enabled,
            )
            if entry.compatibility is not Compatibility.SUPPORTED:
                continue
            for target_set_id in decision.target_set_ids:
                target_set = target_sets.get(target_set_id)
                if target_set is None:
                    continue
                mode = CheckMode(decision.mode)
                outbound_tag = decision.outbound_tag or entry.outbound_tag
                inbound_tag = decision.inbound_tag or entry.inbound_tag
                check_id = public_check_id(
                    entry.entry_id,
                    target_set_id,
                    mode.value,
                    decision.selection_id,
                )
                definition = CheckDefinition(
                    check_id=check_id,
                    entry_id=entry.entry_id,
                    source_id=source_id,
                    target_set_id=target_set_id,
                    mode=mode,
                    generation=generation.generation,
                    runtime_lifecycle=decision.runtime_lifecycle,
                    outbound_tag=outbound_tag,
                    inbound_tag=inbound_tag,
                    egress_assertion_ids=list(decision.egress_assertion_ids),
                    enabled=(
                        source.enabled
                        and entry.enabled
                        and decision.enabled
                        and target_set.enabled
                    ),
                )
                compiled[check_id] = CompiledCheck(
                    definition=definition,
                    entry=effective_entry,
                    target_set=target_set,
                    egress_assertions=tuple(
                        assertions[item]
                        for item in decision.egress_assertion_ids
                        if item in assertions
                    ),
                    assignment_reason=decision.rule,
                )

    enabled_checks = [item for item in compiled.values() if item.definition.enabled]
    persistent_profiles = {
        (
            item.definition.entry_id,
            item.definition.mode.value,
            item.definition.outbound_tag,
            item.definition.inbound_tag,
            item.definition.generation,
        )
        for item in enabled_checks
        if item.definition.runtime_lifecycle
        and item.definition.runtime_lifecycle.value == "persistent"
    }
    if len(persistent_profiles) > config.scheduler.max_active_runtimes:
        raise InventoryError(
            "persistent profiles exceed scheduler.max_active_runtimes; "
            "increase the limit or assign fresh lifecycle"
        )
    has_fresh = any(
        item.definition.runtime_lifecycle
        and item.definition.runtime_lifecycle.value == "fresh"
        for item in enabled_checks
    )
    if has_fresh and len(persistent_profiles) >= config.scheduler.max_active_runtimes:
        raise InventoryError(
            "persistent profiles leave no runtime slot for fresh checks; "
            "increase scheduler.max_active_runtimes or change a lifecycle"
        )
    return compiled
