"""Stable public identifiers and conservative source-entry reconciliation."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .models import (
    CheckMode,
    IdentityBindingModel,
    IdentityRegistryModel,
    ImportedEntry,
    clean_display_name,
)


_NAMESPACE = uuid.UUID("ffac231b-f7bc-52dc-bf0b-239452918779")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class IdentityError(ValueError):
    reason = "identity_conflict"


def _existing_or_new(prefix: str, existing: str | None = None) -> str:
    if existing is not None:
        if not _ID_RE.fullmatch(existing):
            raise IdentityError("existing identifier is invalid")
        return existing
    return f"{prefix}_{uuid.uuid4().hex}"


def new_source_id() -> str:
    return _existing_or_new("src")


def stable_source_id(existing: str | None = None) -> str:
    """Keep a persisted ID, or create a random one (never hash a source URL)."""

    return _existing_or_new("src", existing)


def new_entry_id() -> str:
    return _existing_or_new("entry")


def stable_entry_id(existing: str | None = None) -> str:
    """Keep a registry ID, or create a random ID independent of credentials."""

    return _existing_or_new("entry", existing)


def new_target_id() -> str:
    return _existing_or_new("target")


def stable_target_id(stable_key: str | None = None, *, existing: str | None = None) -> str:
    if existing is not None:
        return _existing_or_new("target", existing)
    if stable_key is None:
        return new_target_id()
    value = uuid.uuid5(_NAMESPACE, f"target\0{stable_key}").hex
    return f"target_{value}"


def new_target_set_id() -> str:
    return _existing_or_new("set")


def stable_target_set_id(stable_key: str | None = None, *, existing: str | None = None) -> str:
    if existing is not None:
        return _existing_or_new("set", existing)
    if stable_key is None:
        return new_target_set_id()
    value = uuid.uuid5(_NAMESPACE, f"target-set\0{stable_key}").hex
    return f"set_{value}"


def stable_check_id(
    entry_id: str,
    mode: CheckMode | str,
    target_set_id: str,
    selection_id: str | None = None,
) -> str:
    """Derive a public ID only from durable, already-public identifiers.

    ``selection_id`` is the assignment ID which selected profile routing.  Raw
    inbound/outbound tags are deliberately not accepted here: profile authors
    can put credentials or other private material in those strings, and a
    deterministic public ID would otherwise become an offline oracle for them.
    """

    mode_value = mode.value if isinstance(mode, CheckMode) else CheckMode(mode).value
    parts = ("check-v2", entry_id, mode_value, target_set_id, selection_id or "")
    encoded = "\0".join(parts).encode("utf-8")
    value = hashlib.sha256(encoded).hexdigest()
    return f"check_{value}"


check_id = stable_check_id


def new_generation_id() -> str:
    """Generation IDs are random so no secret-derived digest becomes public."""

    return f"gen_{uuid.uuid4().hex}"


def new_run_id() -> str:
    return f"run_{uuid.uuid4().hex}"


def connection_fingerprint(nonsecret_semantics: Mapping[str, Any]) -> str:
    """Hash caller-selected *non-secret* semantics for the private registry."""

    try:
        encoded = json.dumps(
            nonsecret_semantics,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IdentityError("non-secret identity semantics are not JSON serializable") from exc
    return hashlib.sha256(encoded).hexdigest()


def normalized_identity_name(name: str) -> str:
    return clean_display_name(name).casefold()


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    candidate_id: str
    name_key: str
    connection_fingerprint: str | None = None
    external_id: str | None = None

    @classmethod
    def from_entry(cls, entry: ImportedEntry) -> "CandidateIdentity":
        return cls(
            candidate_id=entry.candidate_id,
            name_key=entry.identity_name or normalized_identity_name(entry.name),
            connection_fingerprint=entry.connection_fingerprint,
            external_id=entry.external_id,
        )


@dataclass(slots=True)
class IdentityBinding:
    entry_id: str
    external_id: str | None = None
    name_key: str | None = None
    connection_fingerprint: str | None = None
    active: bool = True

    @classmethod
    def from_model(cls, model: IdentityBindingModel) -> "IdentityBinding":
        return cls(**model.model_dump())

    def to_model(self) -> IdentityBindingModel:
        return IdentityBindingModel(
            entry_id=self.entry_id,
            external_id=self.external_id,
            name_key=self.name_key,
            connection_fingerprint=self.connection_fingerprint,
            active=self.active,
        )


@dataclass(frozen=True, slots=True)
class IdentityConflict:
    candidate_ids: tuple[str, ...]
    possible_entry_ids: tuple[str, ...]
    message: str


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    source_id: str
    assignments: Mapping[str, str]
    new_entry_ids: tuple[str, ...]
    disappeared_entry_ids: tuple[str, ...]
    conflicts: tuple[IdentityConflict, ...]

    @property
    def ok(self) -> bool:
        return not self.conflicts

    @property
    def requires_manual_reconciliation(self) -> bool:
        return bool(self.conflicts)

    def entry_id_for(self, candidate_id: str) -> str:
        try:
            return self.assignments[candidate_id]
        except KeyError as exc:
            raise IdentityError("candidate has no reconciled entry ID") from exc


class IdentityRegistry:
    """Persisted mapping registry.

    ``reconcile`` is all-or-nothing: when a conflict exists the registry is not
    changed, allowing the caller to retain the complete last-known-good source.
    """

    def __init__(self, sources: Mapping[str, Iterable[IdentityBinding]] | None = None) -> None:
        self.sources: dict[str, list[IdentityBinding]] = {
            source_id: [
                IdentityBinding(
                    entry_id=item.entry_id,
                    external_id=item.external_id,
                    name_key=item.name_key,
                    connection_fingerprint=item.connection_fingerprint,
                    active=item.active,
                )
                for item in bindings
            ]
            for source_id, bindings in (sources or {}).items()
        }

    @classmethod
    def from_model(cls, value: IdentityRegistryModel | Mapping[str, Any]) -> "IdentityRegistry":
        model = value if isinstance(value, IdentityRegistryModel) else IdentityRegistryModel.model_validate(value)
        return cls(
            {
                source_id: [IdentityBinding.from_model(binding) for binding in bindings]
                for source_id, bindings in model.sources.items()
            }
        )

    def to_model(self) -> IdentityRegistryModel:
        return IdentityRegistryModel(
            sources={
                source_id: [binding.to_model() for binding in bindings]
                for source_id, bindings in self.sources.items()
            }
        )

    def prune_unmatchable_inactive(self) -> int:
        """Drop inactive rows that contain no key reconciliation could use."""

        removed = 0
        for source_id, bindings in list(self.sources.items()):
            retained = [
                binding
                for binding in bindings
                if binding.active
                or binding.external_id is not None
                or binding.name_key is not None
                or binding.connection_fingerprint is not None
            ]
            removed += len(bindings) - len(retained)
            if retained:
                self.sources[source_id] = retained
            else:
                self.sources.pop(source_id, None)
        return removed

    def reconcile(
        self,
        source_id: str,
        candidates: Iterable[CandidateIdentity | ImportedEntry],
        *,
        apply: bool = True,
    ) -> ReconciliationResult:
        normalized = [
            item if isinstance(item, CandidateIdentity) else CandidateIdentity.from_entry(item)
            for item in candidates
        ]
        candidate_ids = [item.candidate_id for item in normalized]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise IdentityError("candidate IDs are not unique")
        previous = self.sources.get(source_id, [])
        assignments: dict[str, str] = {}
        used_entries: set[str] = set()
        conflicts: list[IdentityConflict] = []

        def available(items: Iterable[IdentityBinding]) -> list[IdentityBinding]:
            return [item for item in items if item.entry_id not in used_entries]

        # A source-provided stable identity is authoritative. Duplicate values
        # are a conflict rather than an invitation to merge entries.
        external_candidates: dict[str, list[CandidateIdentity]] = {}
        external_previous: dict[str, list[IdentityBinding]] = {}
        for candidate in normalized:
            if candidate.external_id:
                external_candidates.setdefault(candidate.external_id, []).append(candidate)
        for binding in previous:
            if binding.external_id:
                external_previous.setdefault(binding.external_id, []).append(binding)
        for external_id, group in external_candidates.items():
            old = external_previous.get(external_id, [])
            if len(group) > 1 or len(old) > 1:
                conflicts.append(
                    IdentityConflict(
                        tuple(item.candidate_id for item in group),
                        tuple(item.entry_id for item in old),
                        "duplicate source-provided stable identity",
                    )
                )
            elif len(old) == 1:
                assignments[group[0].candidate_id] = old[0].entry_id
                used_entries.add(old[0].entry_id)

        unresolved = [item for item in normalized if item.candidate_id not in assignments]
        blocked = {item_id for conflict in conflicts for item_id in conflict.candidate_ids}

        # A unique name inside this candidate source retains identity across a
        # credentials rotation. It may only match one existing registry row.
        candidate_names: dict[str, list[CandidateIdentity]] = {}
        previous_names: dict[str, list[IdentityBinding]] = {}
        for candidate in unresolved:
            if candidate.candidate_id not in blocked:
                candidate_names.setdefault(candidate.name_key, []).append(candidate)
        for binding in previous:
            if binding.name_key:
                previous_names.setdefault(binding.name_key, []).append(binding)
        for name_key, group in candidate_names.items():
            old = available(previous_names.get(name_key, []))
            if len(group) == 1 and len(old) == 1:
                assignments[group[0].candidate_id] = old[0].entry_id
                used_entries.add(old[0].entry_id)

        # Duplicate names (and recognizable renames) are matched only when the
        # non-secret semantics make a one-to-one result.
        unresolved = [
            item
            for item in normalized
            if item.candidate_id not in assignments and item.candidate_id not in blocked
        ]
        candidate_fingerprints: dict[str, list[CandidateIdentity]] = {}
        previous_fingerprints: dict[str, list[IdentityBinding]] = {}
        for candidate in unresolved:
            if candidate.connection_fingerprint:
                candidate_fingerprints.setdefault(candidate.connection_fingerprint, []).append(candidate)
        for binding in previous:
            if binding.connection_fingerprint:
                previous_fingerprints.setdefault(binding.connection_fingerprint, []).append(binding)
        for fingerprint, group in candidate_fingerprints.items():
            old = available(previous_fingerprints.get(fingerprint, []))
            if len(group) == 1 and len(old) == 1:
                assignments[group[0].candidate_id] = old[0].entry_id
                used_entries.add(old[0].entry_id)
            elif old:
                conflict = IdentityConflict(
                    tuple(item.candidate_id for item in group),
                    tuple(item.entry_id for item in old),
                    "entries cannot be distinguished by non-secret semantics",
                )
                conflicts.append(conflict)
                blocked.update(conflict.candidate_ids)

        # If duplicate historical names remain after semantic matching, a
        # changed candidate cannot be assigned to one of them arbitrarily.
        unresolved = [
            item
            for item in normalized
            if item.candidate_id not in assignments and item.candidate_id not in blocked
        ]
        unresolved_names: dict[str, list[CandidateIdentity]] = {}
        for candidate in unresolved:
            unresolved_names.setdefault(candidate.name_key, []).append(candidate)
        for name_key, group in unresolved_names.items():
            old = available(previous_names.get(name_key, []))
            if old:
                conflict = IdentityConflict(
                    tuple(item.candidate_id for item in group),
                    tuple(item.entry_id for item in old),
                    "changed entries with this name require manual reconciliation",
                )
                conflicts.append(conflict)
                blocked.update(conflict.candidate_ids)

        # Identical brand-new duplicates also require the reconciliation UI.
        unresolved = [
            item
            for item in normalized
            if item.candidate_id not in assignments and item.candidate_id not in blocked
        ]
        duplicate_groups: dict[tuple[str, str | None], list[CandidateIdentity]] = {}
        for candidate in unresolved:
            duplicate_groups.setdefault(
                (candidate.name_key, candidate.connection_fingerprint), []
            ).append(candidate)
        for group in duplicate_groups.values():
            if len(group) > 1:
                conflict = IdentityConflict(
                    tuple(item.candidate_id for item in group),
                    (),
                    "new entries are indistinguishable",
                )
                conflicts.append(conflict)
                blocked.update(conflict.candidate_ids)

        new_ids: list[str] = []
        for candidate in normalized:
            if candidate.candidate_id in assignments or candidate.candidate_id in blocked:
                continue
            entry_id = new_entry_id()
            assignments[candidate.candidate_id] = entry_id
            new_ids.append(entry_id)

        disappeared = tuple(
            item.entry_id for item in previous if item.active and item.entry_id not in used_entries
        )
        result = ReconciliationResult(
            source_id=source_id,
            assignments=dict(assignments),
            new_entry_ids=tuple(new_ids),
            disappeared_entry_ids=disappeared,
            conflicts=tuple(conflicts),
        )
        if apply and result.ok:
            by_entry = {item.entry_id: item for item in previous}
            for item in previous:
                item.active = False
            for candidate in normalized:
                entry_id = assignments[candidate.candidate_id]
                binding = by_entry.get(entry_id)
                if binding is None:
                    binding = IdentityBinding(entry_id=entry_id)
                    previous.append(binding)
                    by_entry[entry_id] = binding
                binding.external_id = candidate.external_id
                binding.name_key = candidate.name_key
                binding.connection_fingerprint = candidate.connection_fingerprint
                binding.active = True
            self.sources[source_id] = previous
        return result

    def apply_manual_mapping(
        self,
        source_id: str,
        candidates: Iterable[CandidateIdentity | ImportedEntry],
        mapping: Mapping[str, str],
    ) -> ReconciliationResult:
        normalized = [
            item if isinstance(item, CandidateIdentity) else CandidateIdentity.from_entry(item)
            for item in candidates
        ]
        ids = {item.candidate_id for item in normalized}
        if set(mapping) != ids or len(set(mapping.values())) != len(mapping):
            raise IdentityError("manual mapping must assign every candidate exactly once")
        previous = self.sources.get(source_id, [])
        known = {item.entry_id for item in previous}
        other_source_ids = {
            binding.entry_id
            for other_source_id, bindings in self.sources.items()
            if other_source_id != source_id
            for binding in bindings
        }
        if set(mapping.values()) & other_source_ids:
            raise IdentityError("manual mapping reuses an entry ID from another source")
        for entry_id in mapping.values():
            if entry_id not in known and not _ID_RE.fullmatch(entry_id):
                raise IdentityError("manual mapping contains an invalid entry ID")
        for binding in previous:
            binding.active = False
        by_entry = {item.entry_id: item for item in previous}
        for candidate in normalized:
            entry_id = mapping[candidate.candidate_id]
            binding = by_entry.get(entry_id)
            if binding is None:
                binding = IdentityBinding(entry_id=entry_id)
                previous.append(binding)
                by_entry[entry_id] = binding
            binding.external_id = candidate.external_id
            binding.name_key = candidate.name_key
            binding.connection_fingerprint = candidate.connection_fingerprint
            binding.active = True
        self.sources[source_id] = previous
        new_ids = tuple(entry_id for entry_id in mapping.values() if entry_id not in known)
        active = set(mapping.values())
        disappeared = tuple(item.entry_id for item in previous if item.entry_id not in active)
        return ReconciliationResult(source_id, dict(mapping), new_ids, disappeared, ())


def reconcile_entries(
    source_id: str,
    previous_registry: IdentityRegistry | IdentityRegistryModel | Mapping[str, Any],
    candidates: Iterable[CandidateIdentity | ImportedEntry],
    *,
    apply: bool = True,
) -> ReconciliationResult:
    registry = (
        previous_registry
        if isinstance(previous_registry, IdentityRegistry)
        else IdentityRegistry.from_model(previous_registry)
    )
    return registry.reconcile(source_id, candidates, apply=apply)


__all__ = [
    "CandidateIdentity",
    "IdentityBinding",
    "IdentityConflict",
    "IdentityError",
    "IdentityRegistry",
    "ReconciliationResult",
    "check_id",
    "connection_fingerprint",
    "new_entry_id",
    "new_generation_id",
    "new_run_id",
    "new_source_id",
    "new_target_id",
    "new_target_set_id",
    "normalized_identity_name",
    "reconcile_entries",
    "stable_check_id",
    "stable_entry_id",
    "stable_source_id",
    "stable_target_id",
    "stable_target_set_id",
]
