"""Shared application layer used by CLI, FastAPI, scheduler, and control socket."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .checker import Checker
from .config import config_to_dict
from .config import load_config as _load_config
from .config import validate_config
from .config import save_config as _save_config
from .control import ControlServer
from .identity import IdentityRegistry, new_generation_id, new_run_id
from .importers import MAX_ENTRIES, SourceImportError, import_content
from .inventory import CompiledCheck, InventoryError, compile_inventory
from .metrics import Metrics
from .models import (
    AppConfig,
    EgressState,
    IdentityRegistryModel,
    ReachabilityState,
    Reason,
    RunResult,
    SourceGeneration,
    utc_now,
)
from .runtime import (
    EffectiveConfigError,
    XrayRuntimeError,
    XrayRuntimeManager,
    validate_imported_profile,
)
from .runtime_pool import RuntimePool
from .scheduler import ScheduledCheck, Scheduler, SchedulerAdmissionError
from .security import redact_text
from .sources import SourceFetchError, SourceLoader
from .storage import DataStore, FileLock, StorageError

logger = logging.getLogger(__name__)


class ServiceError(RuntimeError):
    pass


class _ConfigApplyCommittedCancellation(asyncio.CancelledError):
    """Cancellation delivered only after a committed executor swap was finalized."""


@dataclass(slots=True)
class SourceStatus:
    source_id: str
    refresh_success: bool | None = None
    last_success_timestamp: float = 0
    last_attempt_timestamp: float = 0
    reason: str | None = None
    detail: str | None = None
    candidate_count: int | None = None

    def public_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "refresh_success": self.refresh_success,
            "last_success_timestamp": self.last_success_timestamp,
            "last_attempt_timestamp": self.last_attempt_timestamp,
            "reason": self.reason,
            "detail": self.detail,
            "candidate_count": self.candidate_count,
        }


def load_app_config(path: str | Path) -> AppConfig:
    return _load_config(path)


def save_app_config(config: AppConfig, path: str | Path) -> None:
    _save_config(config, path)


def _config_revision(config: AppConfig | None) -> str | None:
    if config is None:
        return None
    serialized = json.dumps(
        config_to_dict(config, reveal_secrets=True),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _entries_equal(previous: list[Any], candidate: list[Any]) -> bool:
    def normalized(entry: Any) -> dict[str, Any]:
        return entry.model_dump(mode="json", exclude={"generation"}, exclude_none=True)

    return [normalized(item) for item in previous] == [normalized(item) for item in candidate]


def _referenced_secret_files(config: AppConfig, *, base_dir: Path) -> set[Path]:
    """Return configured file-backed secret paths without reading their values."""

    paths: set[Path] = set()
    for source in config.sources:
        references = [source.location_ref, *source.headers_ref.values()]
        for reference in references:
            if reference is None or reference.file is None:
                continue
            path = Path(reference.file)
            paths.add((base_dir / path if not path.is_absolute() else path).resolve())
    return paths


async def _critical_to_thread(function: Any, /, *args: Any, **kwargs: Any) -> Any:
    """Finish a state-file operation even if its asyncio owner is cancelled."""

    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError as exc:
            if task.done():
                # Preserve cancellation originating in the worker task instead
                # of spinning on an already-complete task.
                task.result()
            cancellation = exc
            continue
    if cancellation is not None:
        raise cancellation
    return result


async def _finish_committed(coroutine: Any) -> Any:
    """Finish post-commit async cleanup before propagating cancellation."""

    task = asyncio.create_task(coroutine)
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError as exc:
            # Distinguish cancellation of this caller from a coroutine that
            # cancelled itself. Without this check an internally-cancelled
            # cleanup task would make this loop spin forever.
            if task.done():
                task.result()
            cancellation = exc
            continue
    if cancellation is not None:
        raise _ConfigApplyCommittedCancellation() from cancellation
    return result


async def fetch_source_candidates(source: Any, loader: SourceLoader) -> list[Any]:
    """Load and parse one source without mutating accepted state.

    The setup/reconciliation UI and daemon refresh intentionally share this
    function so format handling cannot drift between interactive and scheduled
    operation.
    """

    payload = await loader.fetch(source)
    documents = payload.documents or (payload.content,)
    candidates: list[Any] = []
    for document_index, document in enumerate(documents, 1):
        parsed = import_content(document, source.format, source_id=source.source_id)
        if len(documents) > 1:
            parsed = [
                item.model_copy(
                    update={"candidate_id": f"d{document_index:04d}_{item.candidate_id}"}
                )
                for item in parsed
            ]
        for item in parsed:
            if isinstance(item.profile, dict):
                try:
                    validate_imported_profile(item)
                except EffectiveConfigError as exc:
                    raise SourceImportError(
                        f"entry {item.candidate_id}: {exc}"
                    ) from exc
        candidates.extend(parsed)
        if len(candidates) > MAX_ENTRIES:
            raise SourceImportError("source contains too many entries")
    return candidates


class ProberService:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        config_path: str | Path | None = None,
        xray_binary: str | Path = "xray",
        runtime_dir: str | Path | None = None,
        schedule_enabled: bool = True,
        control_enabled: bool = True,
    ) -> None:
        self.store = DataStore(data_dir)
        self.data_dir = self.store.root
        self.config_path = Path(config_path) if config_path else self.store.config_path
        self.xray_binary = os.fspath(xray_binary)
        configured_runtime_dir = runtime_dir or os.environ.get("PROBER_RUNTIME_DIR")
        self.runtime_dir = (
            Path(configured_runtime_dir) if configured_runtime_dir is not None else None
        )
        self.schedule_enabled = schedule_enabled
        self.control_enabled = control_enabled
        self.control_path = self.data_dir / "control.sock"
        self.config: AppConfig | None = None
        self.generations: dict[str, SourceGeneration] = {}
        self.identity = IdentityRegistry()
        self.inventory: dict[str, CompiledCheck] = {}
        self.results: dict[str, RunResult] = {}
        self.errors: dict[str, Counter[str]] = {}
        self.source_status: dict[str, SourceStatus] = {}
        self.config_reload_success = False
        self.ready = False
        self.main_loop_alive = False
        # Relative secret references are resolved next to the persisted config,
        # which is the data directory in the supported deployment layout.
        self._loader = SourceLoader(base_dir=self.config_path.parent)
        self._refresh_locks: dict[str, asyncio.Lock] = {}
        self._mutation_lock = asyncio.Lock()
        self._lifecycle_lock = asyncio.Lock()
        self._stop_lock = asyncio.Lock()
        self._stop_task: asyncio.Task[None] | None = None
        self._stopping = False
        self._refresh_tasks: list[asyncio.Task[None]] = []
        self._loaded_result_ids: set[str] = set()
        self._manager: XrayRuntimeManager | None = None
        self._pool: RuntimePool | None = None
        self._checker: Checker | None = None
        self._scheduler: Scheduler | None = None
        self._control: ControlServer | None = None
        self._data_lock: FileLock | None = None
        self.metrics = Metrics(self.status_snapshot)

    @classmethod
    def from_paths(
        cls,
        *,
        data_dir: str | Path | None = None,
        config_path: str | Path | None = None,
        xray_binary: str | Path | None = None,
        schedule_enabled: bool = True,
        control_enabled: bool = True,
    ) -> "ProberService":
        resolved_data = Path(data_dir or os.environ.get("PROBER_DATA_DIR", "./data"))
        resolved_config = config_path or os.environ.get("PROBER_CONFIG")
        binary = xray_binary or os.environ.get("XRAY_BINARY", "xray")
        return cls(
            resolved_data,
            config_path=resolved_config,
            xray_binary=binary,
            schedule_enabled=schedule_enabled,
            control_enabled=control_enabled,
        )

    async def start(self) -> None:
        # Startup, shutdown, and competing starts own the process resources as
        # one serialized lifecycle.  In particular, no second start can replace
        # ``_data_lock`` while the first acquisition is still in a worker
        # thread.
        async with self._lifecycle_lock:
            if self.main_loop_alive:
                return
            self._stopping = False
            try:
                self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                try:
                    self.data_dir.chmod(0o700)
                except OSError:
                    pass

                data_lock = self.store.lock(timeout=0)
                try:
                    await _critical_to_thread(data_lock.acquire)
                except BaseException:
                    # Cancellation is delivered by ``_critical_to_thread`` only
                    # after acquire has finished, so a locally-owned lock can
                    # always be released before this start exits.
                    if data_lock.acquired:
                        await _critical_to_thread(data_lock.release)
                    raise
                self._data_lock = data_lock
                self.main_loop_alive = True

                await _critical_to_thread(
                    self.store.recover_config_replace, self.config_path
                )
                self._ensure_mutations_allowed()
                await _critical_to_thread(self.store.prune_source_histories)
                self._ensure_mutations_allowed()
                await _critical_to_thread(self._load_identity)
                self._ensure_mutations_allowed()
                await _critical_to_thread(self._load_generations)
                self._ensure_mutations_allowed()
                await _critical_to_thread(self._load_results_as_stale)
                self._ensure_mutations_allowed()
                if self.config_path.exists():
                    try:
                        config = await _critical_to_thread(
                            load_app_config, self.config_path
                        )
                        await self._apply_config(config)
                        self.config_reload_success = True
                        await self._prune_transaction_secrets(config)
                    except Exception as exc:
                        self.config_reload_success = False
                        logger.error("configuration rejected: %s", redact_text(exc))
                else:
                    await _critical_to_thread(
                        self.store.prune_transaction_secrets, set()
                    )
                self._ensure_mutations_allowed()
                if self.control_enabled:
                    self._control = ControlServer(self.control_path, self.handle_control)
                    await self._control.start()
                    self._ensure_mutations_allowed()
            except BaseException:
                # Do not release the lifecycle owner until all partial startup
                # state has been drained. Repeated cancellation of the caller is
                # deferred by ``_finish_committed`` until cleanup completes.
                self._stopping = True
                self.ready = False
                self.main_loop_alive = False
                try:
                    await _finish_committed(self._stop_locked())
                except asyncio.CancelledError:
                    # The original startup exception (normally cancellation) is
                    # authoritative; cleanup has nevertheless completed.
                    pass
                except Exception:
                    logger.error("failed to clean up interrupted service startup")
                raise

    async def stop(self) -> None:
        cleanup = self._stop_task
        if cleanup is None or cleanup.done():
            cleanup = asyncio.create_task(
                self._stop_once(), name="prober-service-shutdown"
            )
            self._stop_task = cleanup
        cancellation: asyncio.CancelledError | None = None
        while True:
            try:
                await asyncio.shield(cleanup)
                break
            except asyncio.CancelledError as exc:
                if cleanup.done():
                    # An internal cancellation is a cleanup failure, not a reason
                    # to spin forever awaiting an already-cancelled task.
                    cleanup.result()
                cancellation = exc
                continue
        if self._stop_task is cleanup:
            self._stop_task = None
        if cancellation is not None:
            raise cancellation

    async def _stop_once(self) -> None:
        # Advertise shutdown before waiting behind an in-progress startup or
        # mutation. This is also the readiness fence consumed by _apply_config.
        self._stopping = True
        self.ready = False
        self.main_loop_alive = False
        async with self._lifecycle_lock:
            await self._stop_locked()

    async def _stop_locked(self) -> None:
        """Release all process resources while holding ``_lifecycle_lock``."""

        async with self._stop_lock:
            self._stopping = True
            self.ready = False
            self.main_loop_alive = False
            failures: list[BaseException] = []

            # Stop accepting mutations first, then cancel and drain every already
            # accepted Unix-control handler before executor/file-lock teardown.
            control, self._control = self._control, None
            if control is not None:
                try:
                    await control.stop()
                except BaseException as exc:
                    failures.append(exc)
                    logger.error("failed to stop control server: %s", redact_text(exc))

            await self._cancel_refresh_tasks()
            async with self._mutation_lock:
                # A direct in-process mutator may have completed while shutdown
                # waited for the lock and may have installed a new refresh set.
                await self._cancel_refresh_tasks()

                scheduler, self._scheduler = self._scheduler, None
                if scheduler is not None:
                    try:
                        await scheduler.stop()
                    except BaseException as exc:
                        failures.append(exc)
                        logger.error("failed to stop scheduler: %s", redact_text(exc))

                pool, self._pool = self._pool, None
                manager, self._manager = self._manager, None
                if pool is not None:
                    try:
                        await pool.close()
                    except BaseException as exc:
                        failures.append(exc)
                        logger.error("failed to close runtime pool: %s", redact_text(exc))
                        if manager is not None:
                            try:
                                await manager.close()
                            except BaseException as manager_exc:
                                failures.append(manager_exc)
                                logger.error(
                                    "failed to close runtime manager: %s",
                                    redact_text(manager_exc),
                                )
                elif manager is not None:
                    try:
                        await manager.close()
                    except BaseException as exc:
                        failures.append(exc)
                        logger.error("failed to close runtime manager: %s", redact_text(exc))
                self._checker = None

            data_lock, self._data_lock = self._data_lock, None
            if data_lock is not None:
                try:
                    await _critical_to_thread(data_lock.release)
                except BaseException as exc:
                    failures.append(exc)
                    logger.error("failed to release data lock: %s", redact_text(exc))

            if failures:
                raise ServiceError("service shutdown encountered cleanup errors") from failures[0]

    async def _cancel_refresh_tasks(self) -> None:
        tasks = tuple(self._refresh_tasks)
        self._refresh_tasks = []
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _ensure_mutations_allowed(self) -> None:
        if self._stopping:
            raise ServiceError("service is stopping")

    async def _apply_config(self, config: AppConfig) -> None:
        configured_source_ids = {item.source_id for item in config.sources}
        candidate_generations = {
            source_id: generation
            for source_id, generation in self.generations.items()
            if source_id in configured_source_ids
        }
        candidate_inventory = compile_inventory(config, candidate_generations)
        # Construct everything that can fail without touching the active
        # executor. A bad runtime directory or invalid limits must not stop a
        # healthy scheduler during a reload.
        manager = XrayRuntimeManager(
            self.xray_binary,
            runtime_dir=self.runtime_dir,
            startup_timeout=config.scheduler.runtime_start_timeout,
        )
        pool = RuntimePool(
            manager,
            limit=config.scheduler.max_active_runtimes,
            restart_backoff_initial=(
                config.scheduler.runtime_restart_backoff_initial
            ),
            restart_backoff_max=config.scheduler.runtime_restart_backoff_max,
            observatory_warmup_delay=config.scheduler.observatory_warmup_delay,
            observatory_warmup_timeout=config.scheduler.observatory_warmup_timeout,
        )
        checker = Checker(
            request_timeout=config.scheduler.request_timeout,
            max_parallel_requests=config.scheduler.max_parallel_requests,
        )
        scheduler = Scheduler(
            self._execute_scheduled,
            concurrency=config.scheduler.max_active_runtimes,
            max_queue=config.scheduler.max_queue_size,
            on_error=self._scheduler_error,
        )
        try:
            await self._validate_inventory(manager, candidate_inventory)
        except BaseException:
            await pool.close()
            raise
        await scheduler.update(
            self._scheduled_checks_for(config, candidate_inventory)
        )

        old_status = self.source_status
        old_manager = self._manager
        old_pool = self._pool
        old_scheduler = self._scheduler
        old_refresh_tasks = list(self._refresh_tasks)

        async def quiesce_and_activate() -> None:
            # Keep the old state installed while its workers drain, but stop
            # advertising readiness as soon as the serialized transition starts.
            # The new scheduler cannot acquire a runtime until the old pool and
            # manager have been fully closed, preserving the configured cap.
            self.ready = False
            for task in old_refresh_tasks:
                task.cancel()
            if old_refresh_tasks:
                await asyncio.gather(*old_refresh_tasks, return_exceptions=True)
            self._refresh_tasks = []
            if old_scheduler is not None:
                await old_scheduler.stop()
            if old_pool is not None:
                await old_pool.close()
            elif old_manager is not None:
                await old_manager.close()

            self.config = config
            self.generations = candidate_generations
            self.inventory = candidate_inventory
            self.source_status = {
                source_id: old_status.get(source_id, SourceStatus(source_id))
                for source_id in configured_source_ids
            }
            self._refresh_locks = {
                source_id: lock
                for source_id, lock in self._refresh_locks.items()
                if source_id in configured_source_ids
            }
            self._manager = manager
            self._pool = pool
            self._checker = checker
            self._scheduler = scheduler
            await self._drop_and_prune_obsolete_results()
            # One-shot CLI work uses the same bounded workers even when periodic
            # producers are disabled for an offline command process.
            await scheduler.start()
            if self.schedule_enabled:
                self._refresh_tasks = [
                    asyncio.create_task(
                        self._refresh_loop(source.source_id),
                        name=f"prober-source-{source.source_id}",
                    )
                    for source in config.sources
                    if source.enabled
                ]
            # Shutdown marks ``_stopping`` before waiting for the mutation
            # lock.  A config apply which was already inside that lock must not
            # resurrect readiness while shutdown is queued behind it.
            self.ready = not self._stopping

        # Quiescing the prior executor and activating the validated replacement
        # are one cancellation-shielded transition. Cancellation is delivered to
        # the caller only after no old/new executor overlap remains.
        try:
            await _finish_committed(quiesce_and_activate())
        except BaseException:
            if self._scheduler is not scheduler:
                await scheduler.stop()
                await pool.close()
            raise

    async def reload_config(self) -> None:
        async with self._mutation_lock:
            self._ensure_mutations_allowed()
            try:
                config = await asyncio.to_thread(load_app_config, self.config_path)
                await self._apply_config(config)
            except _ConfigApplyCommittedCancellation:
                self.config_reload_success = True
                raise
            except Exception:
                self.config_reload_success = False
                raise
            self.config_reload_success = True

    async def replace_config(
        self,
        value: AppConfig | dict[str, Any],
        *,
        expected_revision: str | None = None,
        secrets: dict[str, str] | None = None,
    ) -> None:
        """Validate and atomically replace config through the daemon owner."""

        candidate = validate_config(value)
        secret_values = secrets or {}
        if not isinstance(secret_values, dict) or not all(
            isinstance(name, str) and isinstance(secret, str)
            for name, secret in secret_values.items()
        ):
            raise ServiceError("secret payload is invalid")
        if (
            sum(len(secret.encode("utf-8")) for secret in secret_values.values())
            > 2 * 1024 * 1024
        ):
            raise ServiceError("secret payload exceeds size limit")
        if len(secret_values) > 256:
            raise ServiceError("secret payload contains too many files")
        async with self._mutation_lock:
            self._ensure_mutations_allowed()
            if expected_revision is not None:
                expected_current = (
                    None if expected_revision == "__absent__" else expected_revision
                )
                if expected_current != _config_revision(self.config):
                    raise ServiceError(
                        "configuration changed concurrently; restart the edit"
                    )
            # Compile before touching the accepted file or current service state.
            compile_inventory(candidate, self.generations)
            previous_config = self.config
            try:
                # The prepared journal is durable before either new secrets or
                # the candidate config become visible. Startup rolls it back if
                # the process exits anywhere before the final journal unlink.
                await _critical_to_thread(
                    self.store.begin_config_replace,
                    self.config_path,
                    secret_names=secret_values,
                )
                for name, secret in secret_values.items():
                    await _critical_to_thread(self.store.write_new_secret, name, secret)
                await _critical_to_thread(save_app_config, candidate, self.config_path)
                await self._apply_config(candidate)
            except _ConfigApplyCommittedCancellation:
                # The in-memory swap and its teardown completed. Rolling the
                # durable file back here would split disk from live state.
                await _critical_to_thread(
                    self.store.commit_config_replace, self.config_path
                )
                self.config_reload_success = True
                await self._prune_transaction_secrets(candidate)
                raise
            except BaseException:
                self.config_reload_success = False
                try:
                    await _critical_to_thread(
                        self.store.rollback_config_replace, self.config_path
                    )
                except Exception:
                    logger.error("failed to roll back rejected configuration file")
                if previous_config is not None:
                    await self._prune_transaction_secrets(previous_config)
                raise
            try:
                await _critical_to_thread(
                    self.store.commit_config_replace, self.config_path
                )
            except BaseException:
                # If cancellation arrived after the durable journal unlink, the
                # candidate is already accepted and must remain live.
                try:
                    pending = await asyncio.to_thread(
                        self.store.has_pending_config_replace, self.config_path
                    )
                except Exception:
                    pending = True
                if not pending:
                    self.config_reload_success = True
                    await self._prune_transaction_secrets(candidate)
                    raise
                self.config_reload_success = False
                try:
                    await _critical_to_thread(
                        self.store.rollback_config_replace, self.config_path
                    )
                    if previous_config is not None:
                        await self._apply_config(previous_config)
                        await self._prune_transaction_secrets(previous_config)
                    else:
                        self.ready = False
                except Exception:
                    self.ready = False
                    logger.error("failed to restore service after config commit failure")
                raise
            self.config_reload_success = True
            await self._prune_transaction_secrets(candidate)

    def _scheduled_checks(self) -> list[ScheduledCheck]:
        if self.config is None or not self.schedule_enabled:
            return []
        return self._scheduled_checks_for(self.config, self.inventory)

    def _scheduled_checks_for(
        self, config: AppConfig, inventory: dict[str, CompiledCheck]
    ) -> list[ScheduledCheck]:
        if not self.schedule_enabled:
            return []
        return [
            ScheduledCheck(
                check_id=item.definition.check_id,
                generation=item.definition.generation,
                interval_seconds=config.scheduler.interval,
                payload=item.definition.check_id,
            )
            for item in inventory.values()
            if item.definition.enabled
        ]

    async def _refresh_loop(self, source_id: str) -> None:
        try:
            while True:
                await self.refresh_source(source_id)
                source = self._source(source_id)
                await asyncio.sleep(source.refresh_interval)
        except asyncio.CancelledError:
            raise

    def _source(self, source_id: str) -> Any:
        if self.config is None:
            raise ServiceError("configuration is not loaded")
        for source in self.config.sources:
            if source.source_id == source_id:
                return source
        raise ServiceError("source not found")

    async def _commit_source_state(
        self,
        *,
        generation: SourceGeneration,
        registry: IdentityRegistry,
        generations: dict[str, SourceGeneration],
        inventory: dict[str, CompiledCheck],
        status: SourceStatus,
        reconcile_executor: bool,
    ) -> None:
        """Publish and activate one accepted source state as one transition.

        Validation and identity reconciliation happen before this method.  The
        durable per-source pointer is its commit point: a failed publication
        leaves every live component untouched.  Once that pointer exists, the
        in-memory view and executor bookkeeping must finish even when the
        requesting task is cancelled, otherwise a restart and the running
        process could disagree about the accepted LKG.
        """

        registry_model = registry.to_model()

        async def publish_and_activate() -> None:
            # This thread operation is already protected by the surrounding
            # committed transition; it therefore cannot outlive activation.
            publication_error: Exception | None = None
            for _attempt in range(2):
                try:
                    await asyncio.to_thread(
                        self._publish_source, generation, registry_model
                    )
                    publication_error = None
                    break
                except Exception as exc:
                    # A filesystem failure after atomic rename has an ambiguous
                    # outcome. Retry the idempotent immutable publication once;
                    # if the call still reports failure, inspect the coupled
                    # pointer before deciding whether the commit happened.
                    publication_error = exc
            if publication_error is not None:
                visible = await asyncio.to_thread(
                    self._source_publish_is_visible, generation, registry_model
                )
                if not visible:
                    raise publication_error
                logger.error(
                    "source publication reported failure after commit point",
                    extra={
                        "source_id": generation.source_id,
                        "reason": "internal",
                    },
                )

            # Swap the complete logical view before allowing either executor
            # component to observe the new generation.  The old scheduler may
            # still finish an in-flight check, but its generation guard prevents
            # that result from being published against this inventory.
            self.identity = registry
            self.generations = generations
            self.inventory = inventory
            status.refresh_success = True
            status.last_success_timestamp = time.time()
            status.reason = None
            status.detail = None

            if reconcile_executor:
                # Publish the pool's desired generation before scheduling the
                # new one.  This prevents a new producer from acquiring either
                # an obsolete persistent runtime or a not-yet-desired runtime.
                executor_failed = False
                if self._pool is not None:
                    try:
                        await self._pool.reconcile(
                            item
                            for item in inventory.values()
                            if item.definition.enabled
                        )
                    except Exception:
                        executor_failed = True
                        logger.error(
                            "accepted source state could not reconcile runtime pool",
                            extra={
                                "source_id": generation.source_id,
                                "reason": "internal",
                            },
                        )
                try:
                    await self._drop_and_prune_obsolete_results()
                except Exception:
                    executor_failed = True
                    logger.error(
                        "accepted source state could not prune obsolete results",
                        extra={
                            "source_id": generation.source_id,
                            "reason": "internal",
                        },
                    )
                if self._scheduler is not None and not executor_failed:
                    try:
                        await self._scheduler.update(self._scheduled_checks())
                    except Exception:
                        executor_failed = True
                        logger.error(
                            "accepted source state could not update scheduler",
                            extra={
                                "source_id": generation.source_id,
                                "reason": "internal",
                            },
                        )
                if executor_failed:
                    # The generation is already accepted durably and in memory,
                    # so it must never be reported as a rejected refresh. Quiesce
                    # periodic execution and fail readiness instead. A restart
                    # reconstructs both executor components from the accepted
                    # source pointer.
                    self.ready = False
                    if self._scheduler is not None:
                        try:
                            await self._scheduler.stop()
                        except Exception:
                            logger.error(
                                "failed to quiesce scheduler after source commit",
                                extra={
                                    "source_id": generation.source_id,
                                    "reason": "internal",
                                },
                            )

        await _finish_committed(publish_and_activate())

    async def refresh_source(self, source_id: str) -> SourceStatus:
        # Source fetches are deliberately serialized with config publication and
        # reconciliation. This favors correctness over refresh throughput and
        # prevents whole-registry lost updates.
        lock = self._mutation_lock
        async with lock:
            self._ensure_mutations_allowed()
            # Resolve under the publication lock so a request queued behind a
            # config removal cannot republish that removed source afterward.
            source = self._source(source_id)
            status = self.source_status.setdefault(source_id, SourceStatus(source_id))
            status.last_attempt_timestamp = time.time()
            try:
                candidates = await fetch_source_candidates(source, self._loader)
                status.candidate_count = len(candidates)
                if not candidates and not source.allow_empty:
                    raise SourceImportError("empty source rejected by allow_empty policy")
                reconciliation = self.identity.reconcile(source_id, candidates, apply=False)
                if not reconciliation.ok:
                    raise ServiceError("source entries require identity reconciliation")

                # Apply to a copy first. Publication is a single source-state
                # replace; the process only swaps its in-memory generation after
                # every private file has been durably written.
                candidate_registry = IdentityRegistry.from_model(self.identity.to_model())
                reconciliation = candidate_registry.reconcile(source_id, candidates, apply=True)
                candidate_registry.prune_unmatchable_inactive()
                current_generation = self.generations.get(source_id)
                comparison_generation = (
                    current_generation.generation
                    if current_generation is not None
                    else new_generation_id()
                )
                comparison_entries = [
                    item.to_entry_record(
                        reconciliation.entry_id_for(item.candidate_id), comparison_generation
                    )
                    for item in candidates
                ]
                if current_generation is not None and _entries_equal(
                    current_generation.entries, comparison_entries
                ):
                    await self._commit_source_state(
                        generation=current_generation,
                        registry=candidate_registry,
                        generations=dict(self.generations),
                        inventory=self.inventory,
                        status=status,
                        reconcile_executor=False,
                    )
                    return status
                generation_id = new_generation_id()
                entries = [
                    item.to_entry_record(
                        reconciliation.entry_id_for(item.candidate_id), generation_id
                    )
                    for item in candidates
                ]
                generation = SourceGeneration(
                    source_id=source_id,
                    generation=generation_id,
                    entries=entries,
                    metadata={"entry_count": len(entries)},
                )
                candidate_generations = dict(self.generations)
                candidate_generations[source_id] = generation
                candidate_inventory = compile_inventory(self.config, candidate_generations)
                if self._manager is None:
                    raise ServiceError("runtime manager is not initialized")
                await self._validate_inventory(
                    self._manager, candidate_inventory, source_id=source_id
                )
                await self._commit_source_state(
                    generation=generation,
                    registry=candidate_registry,
                    generations=candidate_generations,
                    inventory=candidate_inventory,
                    status=status,
                    reconcile_executor=True,
                )
            except asyncio.CancelledError:
                raise
            except (
                SourceFetchError,
                SourceImportError,
                ServiceError,
                EffectiveConfigError,
                XrayRuntimeError,
            ) as exc:
                status.refresh_success = False
                status.reason = getattr(exc, "reason", "identity_conflict")
                status.detail = redact_text(exc)
                logger.warning(
                    "source refresh rejected: %s",
                    status.detail,
                    extra={"source_id": source_id, "reason": status.reason},
                )
            except InventoryError as exc:
                status.refresh_success = False
                status.reason = "config_invalid"
                status.detail = redact_text(exc)
                logger.warning(
                    "source candidate exceeds configured capacity: %s",
                    status.detail,
                    extra={"source_id": source_id, "reason": status.reason},
                )
            except Exception:
                status.refresh_success = False
                status.reason = "internal"
                status.detail = "internal source refresh error"
                # Unknown exception messages and tracebacks can contain a
                # credential-bearing source URL. Keep this branch deliberately
                # opaque; expected failures above retain sanitized diagnostics.
                logger.error(
                    "source refresh failed",
                    extra={"source_id": source_id, "reason": "internal"},
                )
            return status

    async def refresh_sources(self, source_id: str | None = None) -> list[dict[str, Any]]:
        if self.config is None:
            raise ServiceError("configuration is not loaded")
        ids = [source_id] if source_id else [item.source_id for item in self.config.sources]
        results = await asyncio.gather(*(self.refresh_source(item) for item in ids))
        return [item.public_dict() for item in results]

    async def preview_reconciliation(self, source_id: str) -> dict[str, Any]:
        """Return only safe candidate metadata and identity choices."""

        lock = self._mutation_lock
        async with lock:
            self._ensure_mutations_allowed()
            source = self._source(source_id)
            candidates = await fetch_source_candidates(source, self._loader)
            if not candidates and not source.allow_empty:
                raise SourceImportError("empty source rejected by allow_empty policy")
            reconciliation = self.identity.reconcile(source_id, candidates, apply=False)
            revision = self._candidate_revision(source_id, candidates)
        return {
            "source_id": source_id,
            "revision": revision,
            "candidates": [item.public_dict() for item in candidates],
            "assignments": dict(reconciliation.assignments),
            "conflicts": [
                {
                    "candidate_ids": list(item.candidate_ids),
                    "possible_entry_ids": list(item.possible_entry_ids),
                    "message": item.message,
                }
                for item in reconciliation.conflicts
            ],
            "disappeared_entry_ids": list(reconciliation.disappeared_entry_ids),
        }

    async def reconcile_source(
        self,
        source_id: str,
        mapping: dict[str, str],
        *,
        expected_revision: str,
    ) -> dict[str, Any]:
        """Accept a manually reconciled source generation atomically."""

        if not isinstance(mapping, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in mapping.items()
        ):
            raise ServiceError("identity mapping must contain string IDs")
        if not isinstance(expected_revision, str) or not expected_revision:
            raise ServiceError("candidate revision is required")
        lock = self._mutation_lock
        async with lock:
            self._ensure_mutations_allowed()
            source = self._source(source_id)
            candidates = await fetch_source_candidates(source, self._loader)
            if not candidates and not source.allow_empty:
                raise SourceImportError("empty source rejected by allow_empty policy")
            if expected_revision != self._candidate_revision(source_id, candidates):
                raise ServiceError(
                    "source candidates changed concurrently; restart reconciliation"
                )
            candidate_registry = IdentityRegistry.from_model(self.identity.to_model())
            reconciliation = candidate_registry.apply_manual_mapping(
                source_id, candidates, mapping
            )
            candidate_registry.prune_unmatchable_inactive()
            current_generation = self.generations.get(source_id)
            comparison_generation = (
                current_generation.generation
                if current_generation is not None
                else new_generation_id()
            )
            comparison_entries = [
                item.to_entry_record(
                    reconciliation.entry_id_for(item.candidate_id), comparison_generation
                )
                for item in candidates
            ]
            status = self.source_status.setdefault(source_id, SourceStatus(source_id))
            status.last_attempt_timestamp = time.time()
            status.candidate_count = len(candidates)
            if current_generation is not None and _entries_equal(
                current_generation.entries, comparison_entries
            ):
                await self._commit_source_state(
                    generation=current_generation,
                    registry=candidate_registry,
                    generations=dict(self.generations),
                    inventory=self.inventory,
                    status=status,
                    reconcile_executor=False,
                )
                return {
                    "source_id": source_id,
                    "generation": current_generation.generation,
                    "entry_count": len(candidates),
                    "changed": False,
                }

            generation_id = new_generation_id()
            generation = SourceGeneration(
                source_id=source_id,
                generation=generation_id,
                entries=[
                    item.to_entry_record(
                        reconciliation.entry_id_for(item.candidate_id), generation_id
                    )
                    for item in candidates
                ],
                metadata={"entry_count": len(candidates), "manually_reconciled": True},
            )
            candidate_generations = dict(self.generations)
            candidate_generations[source_id] = generation
            if self.config is None:
                raise ServiceError("configuration is not loaded")
            candidate_inventory = compile_inventory(self.config, candidate_generations)
            if self._manager is None:
                raise ServiceError("runtime manager is not initialized")
            await self._validate_inventory(
                self._manager, candidate_inventory, source_id=source_id
            )
            await self._commit_source_state(
                generation=generation,
                registry=candidate_registry,
                generations=candidate_generations,
                inventory=candidate_inventory,
                status=status,
                reconcile_executor=True,
            )
            return {
                "source_id": source_id,
                "generation": generation_id,
                "entry_count": len(candidates),
                "changed": True,
            }

    def _candidate_revision(self, source_id: str, candidates: list[Any]) -> str:
        registry = self.identity.to_model().model_dump(mode="json")
        generation = self.generations.get(source_id)
        value = {
            "source_id": source_id,
            "config_revision": _config_revision(self.config),
            "generation": generation.generation if generation is not None else None,
            "bindings": registry.get("sources", {}).get(source_id, []),
            "candidates": [item.model_dump(mode="json") for item in candidates],
        }
        serialized = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    async def _validate_inventory(
        self,
        manager: XrayRuntimeManager,
        inventory: dict[str, CompiledCheck],
        *,
        source_id: str | None = None,
    ) -> None:
        validated: set[tuple[str, str, str | None, str | None, str]] = set()
        for check in inventory.values():
            definition = check.definition
            if not definition.enabled or (
                source_id is not None and definition.source_id != source_id
            ):
                continue
            key = (
                definition.entry_id,
                definition.mode.value,
                definition.outbound_tag,
                definition.inbound_tag,
                definition.generation,
            )
            if key in validated:
                continue
            await manager.validate_for(
                check.entry,
                definition.mode,
                outbound_tag=definition.outbound_tag,
                inbound_tag=definition.inbound_tag,
            )
            validated.add(key)

    def _publish_source(
        self, generation: SourceGeneration, registry: IdentityRegistryModel
    ) -> None:
        self.store.publish_source_state(generation, registry)

    def _source_publish_is_visible(
        self, generation: SourceGeneration, registry: IdentityRegistryModel
    ) -> bool:
        """Resolve an ambiguous write error without exposing private content."""

        try:
            persisted_generation = self.store.load_lkg(generation.source_id)
            persisted_registry = self.store.load_identity_registry()
        except Exception:
            return False
        return (
            persisted_generation == generation
            and persisted_registry.sources.get(generation.source_id, [])
            == registry.sources.get(generation.source_id, [])
        )

    async def _prune_transaction_secrets(self, config: AppConfig) -> None:
        try:
            await _critical_to_thread(
                self.store.prune_transaction_secrets,
                _referenced_secret_files(config, base_dir=self.config_path.parent)
            )
        except StorageError:
            logger.warning("unreferenced transaction secrets could not be pruned")

    async def _rebuild_inventory(self) -> None:
        if self.config is None:
            return
        candidate = compile_inventory(self.config, self.generations)
        if self._pool is not None:
            await self._pool.reconcile(
                item for item in candidate.values() if item.definition.enabled
            )
        self.inventory = candidate
        await self._drop_and_prune_obsolete_results()
        if self._scheduler is not None:
            await self._scheduler.update(self._scheduled_checks())

    def _drop_obsolete_results(self) -> None:
        revision = _config_revision(self.config)
        for check_id, result in list(self.results.items()):
            check = self.inventory.get(check_id)
            if (
                check is None
                or check.definition.generation != result.generation
                or result.config_revision != revision
            ):
                self.results.pop(check_id, None)
                self._loaded_result_ids.discard(check_id)
        for check_id in set(self.errors).difference(self.inventory):
            self.errors.pop(check_id, None)

    async def _drop_and_prune_obsolete_results(self) -> None:
        """Prune memory immediately and move filesystem cleanup off-loop."""

        self._drop_obsolete_results()
        try:
            await _critical_to_thread(self.store.prune_results, set(self.inventory))
        except StorageError:
            logger.warning("obsolete result files could not be pruned")

    async def _execute_scheduled(self, scheduled: ScheduledCheck) -> RunResult:
        check = self.inventory.get(scheduled.check_id)
        if check is None or check.definition.generation != str(scheduled.generation):
            raise ServiceError("scheduled check belongs to an obsolete generation")
        return await self.execute(check)

    async def execute(self, check: CompiledCheck) -> RunResult:
        if self.config is None or self._pool is None or self._checker is None:
            raise ServiceError("executor is not initialized")
        definition = check.definition
        started = utc_now()
        run_id = new_run_id()
        instance_id = self.config.instance_id
        config_revision = _config_revision(self.config)
        try:
            async with self._pool.acquire(check) as runtime:
                cycle = await self._checker.run_cycle(
                    definition,
                    check.target_set,
                    runtime.socks_port,
                    socks_host=runtime.socks_host,
                    egress_assertions=check.egress_assertions,
                )
            result = RunResult(
                run_id=run_id,
                check_id=definition.check_id,
                instance_id=instance_id,
                source_id=definition.source_id,
                entry_id=definition.entry_id,
                mode=definition.mode,
                target_set_id=definition.target_set_id,
                generation=definition.generation,
                config_revision=config_revision,
                state=cycle.overall_state,
                started_at=cycle.started_at,
                completed_at=cycle.completed_at,
                success_count=cycle.reachability.success_count,
                quorum=cycle.reachability.quorum,
                target_results=cycle.reachability.targets,
                egress_results=cycle.egress,
            )
        except asyncio.CancelledError:
            raise
        except (EffectiveConfigError, XrayRuntimeError) as exc:
            reason_value = getattr(exc, "reason", "internal")
            try:
                reason = Reason(reason_value)
            except ValueError:
                reason = Reason.INTERNAL
            result = RunResult(
                run_id=run_id,
                check_id=definition.check_id,
                instance_id=instance_id,
                source_id=definition.source_id,
                entry_id=definition.entry_id,
                mode=definition.mode,
                target_set_id=definition.target_set_id,
                generation=definition.generation,
                config_revision=config_revision,
                state=ReachabilityState.ERROR,
                started_at=started,
                completed_at=utc_now(),
                quorum=check.target_set.quorum,
                reason=reason,
                error=redact_text(exc, max_length=240),
            )
        except Exception:
            # Unknown exception messages may contain data supplied by an
            # imported profile. Keep the public log boundary opaque.
            logger.error(
                "check execution failed",
                extra={"check_id": definition.check_id, "reason": "internal"},
            )
            result = RunResult(
                run_id=run_id,
                check_id=definition.check_id,
                instance_id=instance_id,
                source_id=definition.source_id,
                entry_id=definition.entry_id,
                mode=definition.mode,
                target_set_id=definition.target_set_id,
                generation=definition.generation,
                config_revision=config_revision,
                state=ReachabilityState.ERROR,
                started_at=started,
                completed_at=utc_now(),
                quorum=check.target_set.quorum,
                reason=Reason.INTERNAL,
                error="internal executor error",
            )
        current = self.inventory.get(definition.check_id)
        if (
            current is not None
            and current.definition.generation == result.generation
            and result.config_revision == _config_revision(self.config)
        ):
            self.results[definition.check_id] = result
            self._loaded_result_ids.discard(definition.check_id)
            self._count_errors(result)
            try:
                await _critical_to_thread(self._save_result, result)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.error(
                    "result persistence failed",
                    extra={"check_id": definition.check_id, "reason": "internal"},
                )
                result = result.model_copy(
                    update={
                        "state": ReachabilityState.ERROR,
                        "completed_at": utc_now(),
                        "success_count": 0,
                        "target_results": [],
                        "egress_results": [],
                        "reason": Reason.INTERNAL,
                        "error": "result persistence failed",
                    }
                )
                self.results[definition.check_id] = result
                self.errors.setdefault(definition.check_id, Counter())[Reason.INTERNAL.value] += 1
        return result

    def _count_errors(self, result: RunResult) -> None:
        counter = self.errors.setdefault(result.check_id, Counter())
        if result.reason:
            counter[result.reason.value] += 1
        for item in result.target_results:
            if item.reason:
                counter[item.reason.value] += 1
        for item in result.egress_results:
            if item.reason:
                counter[item.reason.value] += 1

    async def _scheduler_error(self, check: ScheduledCheck, reason: str) -> None:
        compiled = self.inventory.get(check.check_id)
        if (
            compiled is None
            or not compiled.definition.enabled
            or compiled.definition.generation != str(check.generation)
            or self.config is None
        ):
            return
        self.errors.setdefault(check.check_id, Counter())[reason] += 1
        now = utc_now()
        result = RunResult(
            run_id=new_run_id(),
            check_id=compiled.definition.check_id,
            instance_id=self.config.instance_id,
            source_id=compiled.definition.source_id,
            entry_id=compiled.definition.entry_id,
            mode=compiled.definition.mode,
            target_set_id=compiled.definition.target_set_id,
            generation=compiled.definition.generation,
            config_revision=_config_revision(self.config),
            state=ReachabilityState.ERROR,
            started_at=now,
            completed_at=now,
            quorum=compiled.target_set.quorum,
            reason=Reason.SCHEDULER if reason == "scheduler" else Reason.INTERNAL,
            error=(
                "scheduler could not admit the check"
                if reason == "scheduler"
                else "scheduled execution failed"
            ),
        )
        self.results[check.check_id] = result
        self._loaded_result_ids.discard(check.check_id)
        try:
            await _critical_to_thread(self._save_result, result)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error(
                "scheduler result persistence failed",
                extra={"check_id": check.check_id, "reason": "internal"},
            )

    async def run_checks(self, check_id: str | None = None) -> tuple[list[RunResult], int]:
        if not self.ready:
            raise ServiceError("service is not ready")
        if check_id:
            check = self.inventory.get(check_id)
            if check is None:
                raise ServiceError("check not found")
            if not check.definition.enabled:
                raise ServiceError("check is disabled")
            selected = [check]
        else:
            selected = [
                item for item in self.inventory.values() if item.definition.enabled
            ]
        if not selected:
            return [], 2
        if self._scheduler is None:
            raise ServiceError("scheduler is not initialized")
        results = await asyncio.gather(*(self._run_manual_check(item) for item in selected))
        has_error = any(item.state not in {ReachabilityState.SUCCESS, ReachabilityState.FAILURE} for item in results)
        egress_states = [egress.state for item in results for egress in item.egress_results]
        if has_error or any(
            state in {EgressState.ERROR, EgressState.UNKNOWN, EgressState.STALE}
            for state in egress_states
        ):
            return results, 2
        if any(item.state is ReachabilityState.FAILURE for item in results) or any(
            state is EgressState.MISMATCH for state in egress_states
        ):
            return results, 1
        return results, 0

    async def _run_manual_check(self, check: CompiledCheck) -> RunResult:
        if self._scheduler is None:
            raise ServiceError("scheduler is not initialized")
        definition = check.definition
        scheduled = ScheduledCheck(
            check_id=definition.check_id,
            generation=definition.generation,
            interval_seconds=(
                self.config.scheduler.interval if self.config is not None else 1.0
            ),
            payload=definition.check_id,
        )
        try:
            return await self._scheduler.run_once(scheduled)
        except SchedulerAdmissionError as exc:
            current = self.results.get(definition.check_id)
            if (
                current is not None
                and current.generation == definition.generation
                and current.reason is Reason.SCHEDULER
            ):
                return current
            now = utc_now()
            return RunResult(
                run_id=new_run_id(),
                check_id=definition.check_id,
                instance_id=(
                    self.config.instance_id if self.config is not None else "unconfigured"
                ),
                source_id=definition.source_id,
                entry_id=definition.entry_id,
                mode=definition.mode,
                target_set_id=definition.target_set_id,
                generation=definition.generation,
                config_revision=_config_revision(self.config),
                state=ReachabilityState.ERROR,
                started_at=now,
                completed_at=now,
                quorum=check.target_set.quorum,
                reason=Reason.SCHEDULER,
                error=redact_text(exc, max_length=240),
            )

    def status_snapshot(self) -> dict[str, Any]:
        instance_id = self.config.instance_id if self.config else "unconfigured"
        return {
            "instance_id": instance_id,
            "ready": self.ready,
            "config_reload_success": self.config_reload_success,
            "sources": [item.public_dict() for item in self.source_status.values()],
            "checks": self.checks_snapshot(),
            "runtime_active": self._pool.active_count if self._pool else 0,
            "queue_size": self._scheduler.queue_size if self._scheduler else 0,
        }

    def checks_snapshot(self) -> list[dict[str, Any]]:
        return [self._check_public(item) for item in self.inventory.values()]

    def check_snapshot(self, check_id: str) -> dict[str, Any] | None:
        check = self.inventory.get(check_id)
        return self._check_public(check) if check else None

    def entries_snapshot(self) -> list[dict[str, Any]]:
        checks_by_entry: dict[str, list[str]] = {}
        for check in self.inventory.values():
            checks_by_entry.setdefault(check.definition.entry_id, []).append(
                check.definition.check_id
            )
        result = []
        for generation in self.generations.values():
            for entry in generation.entries:
                public = entry.public_dict()
                public["check_ids"] = sorted(checks_by_entry.get(entry.entry_id, []))
                result.append(public)
        return result

    def _check_public(self, check: CompiledCheck) -> dict[str, Any]:
        definition = check.definition
        result = self.results.get(definition.check_id)
        running = bool(
            self._scheduler and definition.check_id in self._scheduler.running
        )
        base: dict[str, Any] = {
            "check_id": definition.check_id,
            "source_id": definition.source_id,
            "entry_id": definition.entry_id,
            "entry_name": check.entry.name,
            "mode": definition.mode.value,
            "runtime_lifecycle": (
                definition.runtime_lifecycle.value
                if definition.runtime_lifecycle is not None
                else None
            ),
            "target_set_id": definition.target_set_id,
            "target_set_name": check.target_set.name,
            "generation": definition.generation,
            "assignment": check.assignment_reason,
            "running": running,
            "state": "unknown" if definition.enabled else "disabled",
            "last_run_timestamp": 0,
            "age_seconds": None,
            "targets": [
                {
                    "target_id": item.target_id,
                    "state": (
                        "unknown" if definition.enabled and item.enabled else "disabled"
                    ),
                }
                for item in check.target_set.targets
            ],
            "egress": [
                {
                    "assertion_id": item.assertion_id,
                    "state": (
                        "unknown" if definition.enabled and item.enabled else "disabled"
                    ),
                }
                for item in check.egress_assertions
            ],
            "errors_total": dict(self.errors.get(definition.check_id, {})),
        }
        if (
            not definition.enabled
            or result is None
            or result.generation != definition.generation
            or (
                result.config_revision is not None
                and result.config_revision != _config_revision(self.config)
            )
        ):
            return base
        completed = result.completed_at
        age = (datetime.now(UTC) - completed).total_seconds() if completed else None
        stale = definition.check_id in self._loaded_result_ids or bool(
            completed
            and self.config
            and age is not None
            and age > self.config.scheduler.max_result_age
        )
        base.update(
            {
                "state": "stale" if stale else result.state.value,
                "last_run_timestamp": completed.timestamp() if completed else 0,
                "age_seconds": max(0.0, age) if age is not None else None,
                "reason": result.reason.value if result.reason else None,
                "error": result.error,
                "success_count": result.success_count,
                "quorum": result.quorum,
            }
        )
        if stale:
            base["targets"] = [
                {
                    "target_id": target.target_id,
                    "state": "stale" if target.enabled else "disabled",
                }
                for target in check.target_set.targets
            ]
            base["egress"] = [
                {
                    "assertion_id": assertion.assertion_id,
                    "state": "stale" if assertion.enabled else "disabled",
                }
                for assertion in check.egress_assertions
            ]
        else:
            target_results = {item.target_id: item for item in result.target_results}
            rendered_targets: list[dict[str, Any]] = []
            for target in check.target_set.targets:
                item = target_results.get(target.target_id)
                if not target.enabled:
                    rendered_targets.append(
                        {"target_id": target.target_id, "state": "disabled"}
                    )
                elif item is None:
                    rendered_targets.append(
                        {
                            "target_id": target.target_id,
                            "state": (
                                "error"
                                if result.state is ReachabilityState.ERROR
                                else "unknown"
                            ),
                            "reason": (
                                result.reason.value if result.reason else None
                            ),
                            "error": result.error,
                        }
                    )
                else:
                    rendered_targets.append(
                        {
                            "target_id": item.target_id,
                            "state": item.state.value,
                            "reason": item.reason.value if item.reason else None,
                            "http_status": item.http_status,
                            "duration_seconds": item.duration_seconds,
                            "ttfb_seconds": item.ttfb_seconds,
                            "bytes_read": item.bytes_read,
                            "error": item.error,
                        }
                    )
            base["targets"] = rendered_targets
            egress_results = {
                item.assertion_id: item for item in result.egress_results
            }
            rendered_egress: list[dict[str, Any]] = []
            for assertion in check.egress_assertions:
                item = egress_results.get(assertion.assertion_id)
                if not assertion.enabled:
                    rendered_egress.append(
                        {"assertion_id": assertion.assertion_id, "state": "disabled"}
                    )
                elif item is None:
                    rendered_egress.append(
                        {
                            "assertion_id": assertion.assertion_id,
                            "state": (
                                "error"
                                if result.state is ReachabilityState.ERROR
                                else "unknown"
                            ),
                            "reason": (
                                result.reason.value if result.reason else None
                            ),
                            "error": result.error,
                        }
                    )
                else:
                    rendered_egress.append(
                        {
                            "assertion_id": item.assertion_id,
                            "state": item.state.value,
                            "reason": item.reason.value if item.reason else None,
                            "observed_ip": item.observed_ip,
                            "duration_seconds": item.duration_seconds,
                            "error": item.error,
                        }
                    )
            base["egress"] = rendered_egress
        return base

    async def handle_control(self, command: str, params: dict[str, Any]) -> Any:
        if command == "ping":
            return {"pong": True}
        if command == "status":
            return self.status_snapshot()
        if command == "checks":
            return self.checks_snapshot()
        if command == "entries":
            return self.entries_snapshot()
        if command == "refresh":
            return await self.refresh_sources(params.get("source_id"))
        if command == "preview_reconciliation":
            source_id = params.get("source_id")
            if not isinstance(source_id, str):
                raise ServiceError("source_id is required")
            return await self.preview_reconciliation(source_id)
        if command == "reconcile":
            source_id = params.get("source_id")
            mapping = params.get("mapping")
            expected_revision = params.get("expected_revision")
            if (
                not isinstance(source_id, str)
                or not isinstance(mapping, dict)
                or not isinstance(expected_revision, str)
            ):
                raise ServiceError(
                    "source_id, mapping, and expected_revision are required"
                )
            return await self.reconcile_source(
                source_id, mapping, expected_revision=expected_revision
            )
        if command == "run":
            results, exit_code = await self.run_checks(params.get("check_id"))
            return {
                "exit_code": exit_code,
                "results": [self._result_public(item) for item in results],
            }
        if command == "reload":
            await self.reload_config()
            return {"reloaded": True}
        if command == "config_for_edit":
            if self.config is None:
                raise ServiceError("configuration is not loaded")
            return {
                "revision": _config_revision(self.config),
                "config": config_to_dict(self.config, reveal_secrets=True),
            }
        if command == "apply_config":
            value = params.get("config")
            if not isinstance(value, dict):
                raise ServiceError("config mapping is required")
            await self.replace_config(
                value,
                expected_revision=params.get("expected_revision"),
                secrets=params.get("secrets"),
            )
            return {"applied": True}
        raise ServiceError("unknown control command")

    @staticmethod
    def _result_public(result: RunResult) -> dict[str, Any]:
        return {
            "run_id": result.run_id,
            "check_id": result.check_id,
            "state": result.state.value,
            "generation": result.generation,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "target_results": [
                {
                    "target_id": item.target_id,
                    "state": item.state.value,
                    "reason": item.reason.value if item.reason else None,
                }
                for item in result.target_results
            ],
            "egress_results": [
                {
                    "assertion_id": item.assertion_id,
                    "state": item.state.value,
                    "reason": item.reason.value if item.reason else None,
                }
                for item in result.egress_results
            ],
        }

    def _source_file(self, source_id: str) -> Path:
        return self.data_dir / "sources" / f"{source_id}.json"

    def _load_generations(self) -> None:
        for source_id in self.store.list_lkg_sources():
            try:
                generation = self.store.load_lkg(source_id)
            except StorageError:
                logger.error("ignored invalid last-known-good source file")
                continue
            if generation is None:
                continue
            self.generations[generation.source_id] = generation
            self.source_status[generation.source_id] = SourceStatus(
                source_id=generation.source_id,
                refresh_success=None,
                last_success_timestamp=generation.accepted_at.timestamp(),
                candidate_count=len(generation.entries),
            )

    def _load_identity(self) -> None:
        try:
            model = self.store.load_identity_registry()
            self.identity = IdentityRegistry.from_model(model)
        except (StorageError, ValidationError, ValueError):
            logger.error("ignored invalid identity registry")

    def _save_result(self, result: RunResult) -> None:
        self.store.save_result(result)

    def _load_results_as_stale(self) -> None:
        try:
            values = self.store.load_results()
        except StorageError:
            logger.error("ignored invalid stored result set")
            return
        for value in values.values():
            try:
                result = RunResult.model_validate(value)
            except (ValidationError, ValueError):
                continue
            # Kept only for API diagnostics if its exact generation is still
            # current. A restart marker forces it stale even when it is recent.
            self.results[result.check_id] = result
            self._loaded_result_ids.add(result.check_id)
