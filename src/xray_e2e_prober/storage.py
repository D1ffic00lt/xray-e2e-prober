"""File-backed state with restrictive permissions, locking and atomic commits."""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import BaseModel

from .models import IdentityRegistryModel, RunResult, SourceGeneration


DEFAULT_DATA_DIR = Path("/data")
DATA_DIR_ENV = "XRAY_E2E_PROBER_DATA_DIR"
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TRANSACTION_SECRET = re.compile(
    r"^.+-[0-9a-f]{32}-(?:location|header-[1-9][0-9]*)$"
)
SOURCE_GENERATION_RETENTION = 3
SOURCE_STATE_RETENTION = 3
_MAX_CONFIG_BACKUP_BYTES = 16 * 1024 * 1024

logger = logging.getLogger(__name__)


class StorageError(RuntimeError):
    pass


class LockTimeoutError(StorageError):
    pass


def resolve_data_dir(value: str | os.PathLike[str] | None = None) -> Path:
    if value is not None:
        return Path(value).expanduser().resolve()
    configured = os.environ.get(DATA_DIR_ENV) or os.environ.get("PROBER_DATA_DIR")
    return Path(configured).expanduser().resolve() if configured else DEFAULT_DATA_DIR


def _safe_component(value: str, label: str) -> str:
    if not _SAFE_COMPONENT.fullmatch(value):
        raise StorageError(f"invalid {label}")
    return value


def ensure_private_directory(path: str | os.PathLike[str]) -> Path:
    directory = Path(path)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError as exc:
        raise StorageError("cannot secure data directory") from exc
    return directory


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int = 0o600,
) -> None:
    """Durably replace one file by writing and fsyncing in the same directory."""

    target = Path(path)
    ensure_private_directory(target.parent)
    file_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        os.fchmod(file_descriptor, mode)
        view = memoryview(data)
        while view:
            written = os.write(file_descriptor, view)
            view = view[written:]
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.replace(temporary_name, target)
        temporary_name = None
        os.chmod(target, mode)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise StorageError("atomic file write failed") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    mode: int = 0o600,
) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def durable_unlink(path: str | os.PathLike[str], *, missing_ok: bool = True) -> None:
    """Remove one file and durably record the directory entry change."""

    target = Path(path)
    try:
        target.unlink()
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileNotFoundError:
        if not missing_ok:
            raise
    except OSError as exc:
        raise StorageError("durable file removal failed") from exc


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict

        return asdict(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"value of type {type(value).__name__} is not JSON serializable")


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    mode: int = 0o600,
    max_bytes: int | None = None,
) -> None:
    try:
        data = json.dumps(
            value,
            default=_json_compatible,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StorageError("state is not JSON serializable") from exc
    if max_bytes is not None and len(data) > max_bytes:
        raise StorageError("state file exceeds size limit")
    atomic_write_bytes(path, data, mode=mode)


def read_json(path: str | os.PathLike[str], *, max_bytes: int = 64 * 1024 * 1024) -> Any:
    file_path = Path(path)
    try:
        if file_path.stat().st_size > max_bytes:
            raise StorageError("state file exceeds size limit")
        raw = file_path.read_bytes()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise StorageError("state file cannot be read") from exc
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise StorageError("state file contains invalid JSON") from exc


class FileLock(AbstractContextManager["FileLock"]):
    """An advisory exclusive lock suitable for CLI/daemon coordination."""

    def __init__(self, path: str | os.PathLike[str], *, timeout: float = 10.0) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self._fd: int | None = None

    @property
    def acquired(self) -> bool:
        return self._fd is not None

    def acquire(self, timeout: float | None = None) -> "FileLock":
        if self._fd is not None:
            raise StorageError("file lock is already acquired")
        ensure_private_directory(self.path.parent)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
            os.fchmod(fd, 0o600)
        except OSError as exc:
            raise StorageError("cannot open data-directory lock") from exc
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fd = fd
                return self
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    os.close(fd)
                    raise StorageError("cannot acquire data-directory lock") from exc
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockTimeoutError("data directory is locked by another process")
                time.sleep(0.05)

    def release(self) -> None:
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.release()

    async def __aenter__(self) -> "FileLock":
        return await asyncio.to_thread(self.acquire)

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await asyncio.to_thread(self.release)


class DataStore:
    """Well-known layout for configuration, LKG generations and latest results."""

    def __init__(self, root: str | os.PathLike[str] | None = None, *, create: bool = True) -> None:
        self.root = resolve_data_dir(root)
        self.config_path = self.root / "config.yaml"
        self.lock_path = self.root / ".prober.lock"
        self.secrets_dir = self.root / "secrets"
        self.lkg_dir = self.root / "lkg"
        self.results_dir = self.root / "results"
        self.identity_path = self.root / "identity-registry.json"
        self.config_transaction_path = self.root / ".config-transaction.json"
        self.config_backup_path = self.root / ".config-previous"
        if create:
            self.initialize()

    def initialize(self) -> None:
        for directory in (self.root, self.secrets_dir, self.lkg_dir, self.results_dir):
            ensure_private_directory(directory)

    def lock(self, *, timeout: float = 10.0) -> FileLock:
        return FileLock(self.lock_path, timeout=timeout)

    locked = lock

    def _secret_path(self, relative_name: str) -> Path:
        relative = Path(relative_name)
        if relative.is_absolute() or not relative.parts or any(
            part in {"", ".", ".."} for part in relative.parts
        ):
            raise StorageError("invalid secret file name")
        for part in relative.parts:
            _safe_component(part, "secret path component")
        candidate = self.secrets_dir.joinpath(*relative.parts)
        ensure_private_directory(candidate.parent)
        return candidate

    def write_secret(self, relative_name: str, value: str | bytes) -> Path:
        data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        path = self._secret_path(relative_name)
        atomic_write_bytes(path, data, mode=0o600)
        return path

    def write_new_secret(self, relative_name: str, value: str | bytes) -> Path:
        """Write a transaction-owned secret without replacing existing data."""

        path = self._secret_path(relative_name)
        if path.exists() or path.is_symlink():
            raise StorageError("secret transaction file already exists")
        return self.write_secret(relative_name, value)

    def read_secret(self, relative_name: str, *, max_bytes: int = 1024 * 1024) -> bytes:
        path = self._secret_path(relative_name)
        try:
            if path.stat().st_size > max_bytes:
                raise StorageError("secret file exceeds size limit")
            return path.read_bytes()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise StorageError("secret file cannot be read") from exc

    def _save_generation_file(self, generation: SourceGeneration) -> Path:
        source_id = _safe_component(generation.source_id, "source ID")
        generation_id = _safe_component(generation.generation, "generation ID")
        source_dir = ensure_private_directory(self.lkg_dir / source_id)
        generations_dir = ensure_private_directory(source_dir / "generations")
        generation_path = generations_dir / f"{generation_id}.json"
        if generation_path.exists():
            try:
                existing = SourceGeneration.model_validate(read_json(generation_path))
            except (StorageError, ValueError) as exc:
                raise StorageError("existing immutable generation is invalid") from exc
            if existing != generation:
                raise StorageError("generation ID is already bound to different content")
            return generation_path
        atomic_write_json(
            generation_path,
            generation,
            mode=0o600,
            max_bytes=64 * 1024 * 1024,
        )
        return generation_path

    def save_source_generation(self, generation: SourceGeneration) -> Path:
        """Write a generation-only commit for callers that own no registry."""

        generation_path = self._save_generation_file(generation)
        source_id = _safe_component(generation.source_id, "source ID")
        generation_id = _safe_component(generation.generation, "generation ID")
        source_dir = ensure_private_directory(self.lkg_dir / source_id)
        # The pointer is committed only after the complete generation is durable.
        atomic_write_json(
            source_dir / "current.json",
            {"schema_version": generation.schema_version, "generation": generation_id},
            mode=0o600,
        )
        self._prune_source_history(source_id)
        return generation_path

    def publish_source_state(
        self,
        generation: SourceGeneration,
        registry: IdentityRegistryModel | BaseModel | Mapping[str, Any],
    ) -> Path:
        """Atomically publish a generation together with its identity bindings.

        Immutable records are made durable first. The single ``current.json``
        rename is the commit point, so recovery sees either the complete old
        state or the complete new state, never a registry/generation mixture.
        """

        model = (
            registry
            if isinstance(registry, IdentityRegistryModel)
            else IdentityRegistryModel.model_validate(registry)
        )
        source_id = _safe_component(generation.source_id, "source ID")
        generation_id = _safe_component(generation.generation, "generation ID")
        source_dir = ensure_private_directory(self.lkg_dir / source_id)
        states_dir = ensure_private_directory(source_dir / "states")
        generation_path = self._save_generation_file(generation)
        state_id = f"state_{uuid.uuid4().hex}"
        atomic_write_json(
            states_dir / f"{state_id}.json",
            {
                "schema_version": generation.schema_version,
                "source_id": source_id,
                "generation": generation_id,
                "bindings": [
                    item.model_dump(mode="json")
                    for item in model.sources.get(source_id, [])
                ],
            },
            mode=0o600,
            max_bytes=64 * 1024 * 1024,
        )
        atomic_write_json(
            source_dir / "current.json",
            {
                "schema_version": generation.schema_version,
                "generation": generation_id,
                "state": state_id,
            },
            mode=0o600,
        )

        # The coupled source pointer above is authoritative. The global file is
        # only a compatibility mirror, so post-commit maintenance is best effort.
        try:
            self.save_identity_registry(model)
        except StorageError:
            logger.warning("identity registry compatibility mirror could not be updated")
        try:
            self._prune_source_history(source_id)
        except StorageError:
            logger.warning("old source-state history could not be pruned")
        return generation_path

    def _load_source_state(
        self, source_id: str, pointer: Mapping[str, Any]
    ) -> tuple[SourceGeneration, list[Any] | None]:
        generation_value = pointer.get("generation")
        if not isinstance(generation_value, str):
            raise StorageError("LKG pointer is invalid")
        generation_id = _safe_component(generation_value, "generation ID")
        state_id = pointer.get("state")
        bindings: list[Any] | None = None
        if state_id is not None:
            if not isinstance(state_id, str):
                raise StorageError("LKG state pointer is invalid")
            state_id = _safe_component(state_id, "state ID")
            try:
                state = read_json(
                    self.lkg_dir / source_id / "states" / f"{state_id}.json"
                )
            except FileNotFoundError as exc:
                raise StorageError("LKG state referenced by pointer is missing") from exc
            if (
                not isinstance(state, dict)
                or state.get("source_id") != source_id
                or state.get("generation") != generation_id
                or not isinstance(state.get("bindings"), list)
            ):
                raise StorageError("LKG source state is invalid")
            try:
                validated = IdentityRegistryModel.model_validate(
                    {"sources": {source_id: state["bindings"]}}
                )
            except ValueError as exc:
                raise StorageError("LKG identity bindings are invalid") from exc
            bindings = validated.sources[source_id]
        try:
            raw = read_json(
                self.lkg_dir / source_id / "generations" / f"{generation_id}.json"
            )
            record = SourceGeneration.model_validate(raw)
        except FileNotFoundError as exc:
            raise StorageError("LKG generation referenced by pointer is missing") from exc
        except ValueError as exc:
            raise StorageError("LKG generation is invalid") from exc
        if record.source_id != source_id or record.generation != generation_id:
            raise StorageError("LKG generation identity does not match its pointer")
        return record, bindings

    def publish_generation(
        self,
        source_id: str,
        generation: str,
        entries: list[Any],
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> SourceGeneration:
        record = SourceGeneration(
            source_id=source_id,
            generation=generation,
            entries=entries,
            metadata=dict(metadata or {}),
        )
        self.save_source_generation(record)
        return record

    def save_lkg(self, generation: SourceGeneration) -> Path:
        return self.save_source_generation(generation)

    def load_lkg(self, source_id: str) -> SourceGeneration | None:
        source_id = _safe_component(source_id, "source ID")
        source_dir = self.lkg_dir / source_id
        pointer_path = source_dir / "current.json"
        try:
            pointer = read_json(pointer_path, max_bytes=64 * 1024)
        except FileNotFoundError:
            return None
        if not isinstance(pointer, dict) or not isinstance(pointer.get("generation"), str):
            raise StorageError("LKG pointer is invalid")
        record, _ = self._load_source_state(source_id, pointer)
        return record

    load_source_generation = load_lkg

    def list_lkg_sources(self) -> list[str]:
        if not self.lkg_dir.exists():
            return []
        return sorted(
            child.name
            for child in self.lkg_dir.iterdir()
            if child.is_dir() and _SAFE_COMPONENT.fullmatch(child.name)
        )

    def save_result(self, result: RunResult | BaseModel | Mapping[str, Any]) -> Path:
        if isinstance(result, Mapping):
            check_id = result.get("check_id")
        else:
            check_id = getattr(result, "check_id", None)
        if not isinstance(check_id, str):
            raise StorageError("result requires check_id")
        check_id = _safe_component(check_id, "check ID")
        path = self.results_dir / f"{check_id}.json"
        atomic_write_json(path, result, mode=0o600)
        return path

    def load_result(self, check_id: str) -> dict[str, Any] | None:
        check_id = _safe_component(check_id, "check ID")
        try:
            value = read_json(self.results_dir / f"{check_id}.json")
        except FileNotFoundError:
            return None
        if not isinstance(value, dict) or value.get("check_id") != check_id:
            raise StorageError("result file identity is invalid")
        return value

    def load_run_result(self, check_id: str) -> RunResult | None:
        value = self.load_result(check_id)
        if value is None:
            return None
        try:
            return RunResult.model_validate(value)
        except ValueError as exc:
            raise StorageError("result file is invalid") from exc

    def load_results(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        if not self.results_dir.exists():
            return results
        for path in sorted(self.results_dir.glob("*.json")):
            check_id = path.stem
            if not _SAFE_COMPONENT.fullmatch(check_id):
                continue
            value = self.load_result(check_id)
            if value is not None:
                results[check_id] = value
        return results

    def prune_results(self, valid_check_ids: Iterable[str]) -> int:
        """Remove persisted latest-result files for checks no longer configured."""

        valid = {_safe_component(item, "check ID") for item in valid_check_ids}
        removed = 0
        if not self.results_dir.exists():
            return removed
        for path in self.results_dir.glob("*.json"):
            if path.stem in valid or not _SAFE_COMPONENT.fullmatch(path.stem):
                continue
            durable_unlink(path)
            removed += 1
        return removed

    def save_identity_registry(
        self, registry: IdentityRegistryModel | BaseModel | Mapping[str, Any]
    ) -> Path:
        atomic_write_json(self.identity_path, registry, mode=0o600)
        return self.identity_path

    def load_identity_registry(self) -> IdentityRegistryModel:
        try:
            value = read_json(self.identity_path)
        except FileNotFoundError:
            value = {}
        try:
            model = IdentityRegistryModel.model_validate(value)
        except ValueError as exc:
            raise StorageError("identity registry is invalid") from exc

        # Per-source state records are authoritative over the compatibility
        # mirror because their pointer is also the generation commit point.
        sources = dict(model.sources)
        for source_id in self.list_lkg_sources():
            pointer_path = self.lkg_dir / source_id / "current.json"
            try:
                pointer = read_json(pointer_path, max_bytes=64 * 1024)
            except FileNotFoundError:
                continue
            if not isinstance(pointer, dict) or "state" not in pointer:
                continue
            _, bindings = self._load_source_state(source_id, pointer)
            assert bindings is not None
            sources[source_id] = bindings
        return IdentityRegistryModel(sources=sources)

    def _prune_source_history(self, source_id: str) -> None:
        source_id = _safe_component(source_id, "source ID")
        source_dir = self.lkg_dir / source_id
        try:
            pointer = read_json(source_dir / "current.json", max_bytes=64 * 1024)
        except FileNotFoundError:
            return
        if not isinstance(pointer, dict) or not isinstance(pointer.get("generation"), str):
            raise StorageError("LKG pointer is invalid")
        current_generation = _safe_component(pointer["generation"], "generation ID")
        current_state = pointer.get("state")
        if current_state is not None:
            if not isinstance(current_state, str):
                raise StorageError("LKG state pointer is invalid")
            current_state = _safe_component(current_state, "state ID")

        states_dir = source_dir / "states"
        retained_states: list[Path] = []
        if states_dir.exists():
            states = sorted(
                (path for path in states_dir.glob("*.json") if path.is_file()),
                key=lambda path: (path.stat().st_mtime_ns, path.name),
                reverse=True,
            )
            current_path = states_dir / f"{current_state}.json" if current_state else None
            if current_path is not None and current_path in states:
                retained_states.append(current_path)
            for path in states:
                if path not in retained_states and len(retained_states) < SOURCE_STATE_RETENTION:
                    retained_states.append(path)
            for path in states:
                if path not in retained_states:
                    durable_unlink(path)

        retained_generations = {current_generation}
        for path in retained_states:
            try:
                value = read_json(path)
            except (FileNotFoundError, StorageError):
                continue
            generation_id = value.get("generation") if isinstance(value, dict) else None
            if isinstance(generation_id, str) and _SAFE_COMPONENT.fullmatch(generation_id):
                retained_generations.add(generation_id)
        generations_dir = source_dir / "generations"
        if not generations_dir.exists():
            return
        generations = sorted(
            (path for path in generations_dir.glob("*.json") if path.is_file()),
            key=lambda path: (path.stat().st_mtime_ns, path.name),
            reverse=True,
        )
        for path in generations:
            if len(retained_generations) >= SOURCE_GENERATION_RETENTION:
                break
            if _SAFE_COMPONENT.fullmatch(path.stem):
                retained_generations.add(path.stem)
        for path in generations:
            if path.stem not in retained_generations:
                durable_unlink(path)

    def prune_source_histories(self) -> None:
        """Bound committed history and artifacts abandoned by a prior crash."""

        for source_id in self.list_lkg_sources():
            self._prune_source_history(source_id)

    @staticmethod
    def _config_target_digest(path: Path) -> str:
        # Identify the configured pathname, not its current symlink target: the
        # atomic replacement itself is allowed to replace a final symlink.
        absolute = os.path.abspath(os.path.expanduser(os.fspath(path)))
        return hashlib.sha256(absolute.encode("utf-8")).hexdigest()

    def begin_config_replace(
        self,
        config_path: str | os.PathLike[str],
        *,
        secret_names: Iterable[str] = (),
    ) -> None:
        """Durably record the old config before a candidate becomes visible."""

        target = Path(config_path)
        if self.config_transaction_path.exists():
            raise StorageError("an unfinished configuration transaction exists")
        transaction_secrets = list(secret_names)
        for name in transaction_secrets:
            path = self._secret_path(name)
            if path.exists() or path.is_symlink():
                raise StorageError("secret transaction file already exists")
        existed = target.exists()
        previous: bytes | None = None
        if existed:
            try:
                if target.stat().st_size > _MAX_CONFIG_BACKUP_BYTES:
                    raise StorageError("configuration backup exceeds size limit")
                previous = target.read_bytes()
            except OSError as exc:
                raise StorageError("configuration cannot be backed up") from exc
            atomic_write_bytes(self.config_backup_path, previous, mode=0o600)
        else:
            durable_unlink(self.config_backup_path, missing_ok=True)
        atomic_write_json(
            self.config_transaction_path,
            {
                "schema_version": 1,
                "target": self._config_target_digest(target),
                "previous_exists": existed,
                "previous_sha256": hashlib.sha256(previous or b"").hexdigest(),
                "secret_names": transaction_secrets,
            },
            mode=0o600,
            max_bytes=64 * 1024,
        )

    def has_pending_config_replace(self, config_path: str | os.PathLike[str]) -> bool:
        if not self.config_transaction_path.exists():
            return False
        value = read_json(self.config_transaction_path, max_bytes=64 * 1024)
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or value.get("target") != self._config_target_digest(Path(config_path))
            or not isinstance(value.get("previous_exists"), bool)
            or not isinstance(value.get("previous_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["previous_sha256"]) is None
            or not isinstance(value.get("secret_names", []), list)
            or not all(isinstance(item, str) for item in value.get("secret_names", []))
        ):
            raise StorageError("configuration transaction journal is invalid")
        for name in value.get("secret_names", []):
            self._secret_path(name)
        return True

    def recover_config_replace(self, config_path: str | os.PathLike[str]) -> bool:
        """Roll back a prepared replacement left by a crash or failed apply."""

        target = Path(config_path)
        if not self.has_pending_config_replace(target):
            # A backup left after the journal commit is no longer authoritative.
            durable_unlink(self.config_backup_path, missing_ok=True)
            return False
        transaction = read_json(self.config_transaction_path, max_bytes=64 * 1024)
        if transaction["previous_exists"]:
            try:
                if self.config_backup_path.stat().st_size > _MAX_CONFIG_BACKUP_BYTES:
                    raise StorageError("configuration transaction backup exceeds size limit")
                previous = self.config_backup_path.read_bytes()
            except StorageError:
                raise
            except OSError as exc:
                raise StorageError("configuration transaction backup is missing") from exc
            if hashlib.sha256(previous).hexdigest() != transaction["previous_sha256"]:
                raise StorageError("configuration transaction backup is invalid")
            atomic_write_bytes(target, previous, mode=0o600)
        else:
            durable_unlink(target, missing_ok=True)
        for name in transaction.get("secret_names", []):
            durable_unlink(self._secret_path(name), missing_ok=True)
        durable_unlink(self.config_transaction_path)
        durable_unlink(self.config_backup_path, missing_ok=True)
        return True

    rollback_config_replace = recover_config_replace

    def commit_config_replace(self, config_path: str | os.PathLike[str]) -> None:
        """Commit the visible candidate by removing its rollback marker."""

        if not self.has_pending_config_replace(config_path):
            raise StorageError("configuration transaction is not prepared")
        # Unlinking the journal is the commit point. Cleanup afterward is best
        # effort so a committed candidate can never be reported as rejected.
        durable_unlink(self.config_transaction_path)
        try:
            durable_unlink(self.config_backup_path, missing_ok=True)
        except StorageError:
            logger.warning("committed configuration backup could not be removed")

    def prune_transaction_secrets(
        self, referenced_files: Iterable[str | os.PathLike[str]]
    ) -> int:
        """Remove unreferenced CLI transaction secret files."""

        referenced = {Path(value).resolve() for value in referenced_files}
        removed = 0
        if not self.secrets_dir.exists():
            return removed
        for path in self.secrets_dir.iterdir():
            if (
                not _TRANSACTION_SECRET.fullmatch(path.name)
                or path.resolve() in referenced
                or not path.is_file()
            ):
                continue
            durable_unlink(path)
            removed += 1
        return removed


__all__ = [
    "DATA_DIR_ENV",
    "DEFAULT_DATA_DIR",
    "DataStore",
    "FileLock",
    "LockTimeoutError",
    "StorageError",
    "atomic_write_bytes",
    "atomic_write_json",
    "atomic_write_text",
    "durable_unlink",
    "ensure_private_directory",
    "read_json",
    "resolve_data_dir",
]
