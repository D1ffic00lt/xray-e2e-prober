# CLI

`prober` предоставляет интерактивную настройку, управление inventory и
однократные проверки поверх того же состояния, которое использует daemon. Эта
страница описывает публичный CLI `0.1.x`; актуальную форму конкретной команды
всегда можно проверить через `prober COMMAND --help`.

## Пути и режим выполнения

Общие параметры путей:

| Параметр | Переменная окружения | Назначение |
| --- | --- | --- |
| `--data-dir PATH` | `PROBER_DATA_DIR` | Каталог конфигурации, state и control socket. |
| `--config PATH` | `PROBER_CONFIG` | Явный путь к YAML вместо `<data-dir>/config.yaml`. |
| `--xray-binary PATH` | `XRAY_BINARY` | Явный путь к Xray для команд, запускающих или проверяющих runtime. |
| — | `PROBER_RUNTIME_DIR` | Абсолютный writable-каталог с временными Xray-конфигурациями; CLI-опции нет. |

Параметр CLI имеет приоритет над переменной окружения. В Compose обычный data
dir — `/data`, Xray уже находится в `PATH`, а `PROBER_RUNTIME_DIR` направлен в
`tmpfs /tmp`. Нативный запуск без этой переменной использует process-private
temporary directory. Детали приведены в
[эксплуатации](operations.md#runtime-файлы-и-ограничения-перезапуска).

Когда `prober serve` работает, команды, которым нужно живое состояние или
executor, используют локальный Unix control socket. При остановленном daemon
поддержанные команды открывают состояние локально и берут блокировку data dir.
Не запускайте второй `serve` или несколько offline-команд на одном каталоге:
одновременно должен существовать только один владелец scheduler/executor.

## Команды

Корневой `prober --help` не читает конфигурацию. Стандартные Typer-опции
`--install-completion` и `--show-completion` устанавливают либо печатают shell
completion и также не открывают state prober.

| Команда | Аргументы и специальные опции | Назначение |
| --- | --- | --- |
| `prober setup` | `--data-dir`, `--config`, `--xray-binary` | Интерактивно создаёт исходную конфигурацию и приватные secret-файлы. |
| `prober serve` | общие пути, `--host`, `--port`, `--log-level` | Запускает один daemon с API, scheduler, control socket и Xray runtimes. |
| `prober subscription add` | общие пути | Интерактивно добавляет HTTP/file/directory source; секретные URL/headers вводятся без публикации в аргументах. |
| `prober subscription list` | `--json`, `--data-dir`, `--config` | Показывает источники без раскрытия credentials. |
| `prober subscription refresh [SOURCE_ID]` | `--json`, общие пути | Атомарно обновляет один source или все sources; effective configs включённых runtime проходят `xray run -test` до публикации, ошибка сохраняет LKG. |
| `prober subscription remove SOURCE_ID` | `--yes`, `--data-dir`, `--config` | Удаляет source после подтверждения, сохраняя его LKG backup; `--yes` пропускает prompt. |
| `prober entries list` | `--json`, `--data-dir`, `--config` | Показывает стабильные entry IDs и эффективное состояние. |
| `prober entries reconcile [SOURCE_ID]` | `--data-dir`, `--config` | Интерактивно разрешает неоднозначные identity mappings одного source; commit сверяет revision повторно загруженного candidate, без ID просит выбрать ровно один source. |
| `prober targets edit` | `--data-dir`, `--config` | Интерактивно редактирует target sets и quorum. |
| `prober assignments edit` | `--data-dir`, `--config` | Интерактивно редактирует индивидуальные и сохранённые правила назначения. |
| `prober egress edit` | `--data-dir`, `--config` | Интерактивно создаёт, заменяет или удаляет egress assertion; при удалении очищает ссылки sources и assignments. |
| `prober check run [CHECK_ID]` | `--once`/`--no-once`, `--json`, общие пути | Выполняет один check или все включённые checks. One-shot — единственный режим `0.1.x`; используйте явный `--once`. |
| `prober status` | `--json`, `--data-dir`, `--config` | Показывает instance, sources, scheduler/queue и краткие состояния checks. |
| `prober config validate [PATH]` | `--json`, `--data-dir`, `--config` | Строго валидирует указанный файл либо выбранную активную конфигурацию без применения. |
| `prober config export` | `--output PATH`/`-o`, `--json`, `--data-dir`, `--config` | Экспортирует переносимый secret-free bundle: конфигурацию, безопасные ID mappings и ожидаемый LKG inventory. |

`serve` намеренно работает с одним application worker. Горизонтальный запуск
нескольких процессов поверх одного `/data` не поддерживается.

## Машиночитаемый вывод

`--json` поддерживают `subscription list`, `subscription refresh`, `entries
list`, `check run`, `status`, `config validate` и `config export`. JSON обычно
пишется в stdout; `config export --output PATH --json` пишет JSON в файл, а в
stdout выводит путь. Диагностику и ненулевой код обрабатывайте отдельно. Не извлекайте
результат автоматизации из человекочитаемых таблиц и не передавайте subscription
URL/token через argv, где их может увидеть список процессов.

В export v2 поля `expected_inventory.sources` и `expected_inventory.checks`
готовы для переноса ID в независимую конфигурацию мониторинга. Registry содержит
opaque `entry_id` и только заново вычисленные безопасные semantic fingerprints;
`external_id`, `name_key`, credentials и raw profile tags не экспортируются.
После переноса задайте новый `instance_id` и повторно заполните secret refs и tag
selectors. Стабильный `assignment_id` сохраняет `check_id` независимо от текста
этих tags.

Примеры:

```console
uv run --locked prober config validate --json
uv run --locked prober subscription refresh primary-vless --json
uv run --locked prober check run ent_example:internet-quorum --once --json
```

Для работающего Compose deployment выполняйте CLI внутри существующего
контейнера, чтобы использовать тот же volume и control socket:

```console
docker compose exec prober prober status --json
docker compose exec prober prober check run --once --json
```

Первичный интерактивный setup до старта daemon остаётся отдельным one-off
контейнером: `docker compose run --rm prober setup --data-dir /data`.

`config validate` проверяет строгую YAML schema и ссылки, но не запускает Xray и
не делает сетевых запросов. Runtime-specific `xray run -test` выполняется при
приёме source generation (включая refresh после `setup`), до смены LKG.

## Коды завершения

| Код | Значение |
| ---: | --- |
| `0` | Команда завершена успешно. Для `check run`: все выбранные checks достигли quorum, а egress assertions совпали либо отключены. |
| `1` | `check run` завершён и обнаружил подтверждённый reachability `failure` или подтверждённый egress `mismatch`. |
| `2` | Ошибка аргументов, конфигурации, control/lock, refresh или executor; для `check run` также неполный, `unknown` либо `error` результат. |

Явная отмена интерактивного wizard также завершается ненулевым кодом оболочки и
не означает probe failure.

Для запуска нескольких checks применяется строгий приоритет: любой
ошибочный/неполный результат даёт `2`; иначе любой подтверждённый
failure/mismatch даёт `1`; только полный успех даёт `0`. Поэтому shell-скрипт не
должен сводить все ненулевые коды к «proxy недоступен».

```sh
if prober check run --once --json >result.json; then
  printf '%s\n' 'all checks passed'
else
  rc=$?
  case "$rc" in
    1) printf '%s\n' 'confirmed probe failure or egress mismatch' >&2 ;;
    2) printf '%s\n' 'configuration/execution error or incomplete result' >&2 ;;
    *) printf 'unexpected exit code: %s\n' "$rc" >&2 ;;
  esac
  exit "$rc"
fi
```
