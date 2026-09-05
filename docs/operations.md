# Эксплуатация

Compose запускает один экземпляр приложения и много Xray child runtimes. Ни
Prometheus, ни панель управления, ни база данных для работы не нужны. Контейнер
не получает Docker socket и не управляет сторонними сервисами.

## Идентичность образа

Исходная сборка закрепляет:

- CPython `3.13.12`, base index digest `sha256:a58daefb915e1e03ad48f3ca4df8832065412c5c35cacb9d39f4229184de12b6`;
- uv `0.12.5`, затем `uv sync --locked --no-dev`;
- Xray Core `26.3.27`;
- Xray SHA-256 `23cd9a…7c8ae` для amd64 и `4d3028…80413c` для arm64.

Dockerfile не поддерживает другие архитектуры молча. Для локальной сборки:

```console
docker compose build --pull prober
```

Публикацию GHCR выполняет `.github/workflows/release.yml` только для Git tags
`vMAJOR.MINOR.PATCH` (допустим SemVer prerelease без `+build`) либо через ручной
запуск с именем уже существующего tag. Пример:

```console
git tag -s v0.1.0 -m 'xray-e2e-prober v0.1.0'
git push origin v0.1.0
```

Workflow собирает один manifest list для `linux/amd64` и `linux/arm64`,
публикует только tags `0.1.0` и `sha-FULL_COMMIT_SHA`, отказывается заменять уже
существующий tag и прикрепляет BuildKit provenance (`mode=max`) и SBOM. Manifest
digest записывается в job summary и artifact `container-*`. Ручной запуск не
создаёт Git tag и принимает только существующий tag, который проходит ту же
проверку. Версия без начального `v` обязана совпадать с
`[project].version` в `pyproject.toml`. Actions закреплены полными commit SHA;
workflow использует только `contents: read` и `packages: write`.

Зафиксируйте показанный manifest digest в deployment:

```console
export PROBER_IMAGE='ghcr.io/OWNER/xray-e2e-prober:0.1.0@sha256:MANIFEST_DIGEST'
```

`OWNER` и `MANIFEST_DIGEST` — обязательные placeholders, а не существующий образ.
Тег `latest` не публикуется и не используется. Build args не предназначены для
секретов: они сохраняются в metadata/history.

## Первичная настройка

Интерактивный рекомендуемый путь:

```console
docker compose build prober
docker compose run --rm prober setup --data-dir /data
docker compose up -d prober
docker compose ps
curl --fail http://127.0.0.1:8080/health/ready
docker compose exec prober prober status
```

`run --rm` и daemon используют named volume `prober-data`, поэтому настройка не
теряется. Если нужен неинтерактивный файл, адаптируйте
`examples/config.example.yaml`, добавьте его в `/data/config.yaml`, а значения
`location_ref`/`headers_ref` предоставьте как Docker secrets. Никогда не
подставляйте subscription URL с token в Compose command или label.

CLI работающего экземпляра:

```console
docker compose exec prober prober subscription list
docker compose exec prober prober subscription refresh
docker compose exec prober prober entries list --json
docker compose exec prober prober check run --once
docker compose exec prober prober status --json
```

Полный справочник команд, опций и кодов завершения: [CLI](cli.md).

Плановый scheduler принадлежит только `prober serve`. Не запускайте второй
daemon на том же `/data`. Однократная команда должна использовать общий executor
или локальный control socket и не создавать конкурирующего владельца состояния.

## Hardening Compose

Пример включает non-root UID/GID `10001`, `read_only`, `cap_drop: ALL`,
`no-new-privileges`, PID/CPU/RAM/no-file limits, ограниченный `tmpfs /tmp` и
отдельный writable `/data`. Публикуется только `127.0.0.1:8080`; SOCKS и control
socket остаются внутри контейнера.

Не меняйте bind на `0.0.0.0` хоста без private network, firewall и аутентификации
на доверенном reverse proxy: API самого MVP read-only, но не многопользовательский.
Xray и приложение находятся в одной resource/security boundary; child process
не является отдельной sandbox.

Compose file secrets на некоторых non-Swarm реализациях являются bind mounts, и
`uid`/`gid`/`mode` могут быть проигнорированы. Храните исходные файлы с mode 0600,
ограничьте доступ к Docker host и проверьте effective mount. Инструкции находятся
в `examples/secrets/README.md`.

Для bind mount вместо named volume заранее создайте узкий каталог и дайте его
UID 10001. Не используйте домашний каталог или корень файловой системы как data
mount. Все `/data` — чувствительная информация: там могут находиться URI,
профили, credentials, last-known-good и identity registry.

### Runtime-файлы и ограничения перезапуска

Compose задаёт `PROBER_RUNTIME_DIR=/tmp/xray-e2e-prober`; сгенерированные
конфигурации Xray тем самым находятся внутри ограниченного `tmpfs /tmp`, а не в
persistent `/data`. При нативном запуске без этой переменной runtime manager
создаёт отдельный process-private temporary directory. Эти файлы содержат
параметры подключений, поэтому переопределение должно указывать на абсолютный
writable и эфемерный путь. Не используйте общий runtime-каталог для нескольких
экземпляров. Штатная остановка удаляет активные файлы, а Compose tmpfs исчезает
вместе с контейнером.

Ошибки старта и неожиданные завершения persistent runtime получают exponential
restart backoff. Интервал начинается с
`scheduler.runtime_restart_backoff_initial` (default 1 s), удваивается до
`runtime_restart_backoff_max` (default 60 s) и относится к конкретным effective
runtime/generation. Пока cooldown активен, цикл получает executor `error`, а не
ложный network `failure`. Успешный fresh start сбрасывает счётчик сразу;
persistent runtime — после наблюдаемого стабильного окна. `initial: 0` отключает
реальную задержку.

Для persistent profile с top-level `observatory`/`burstObservatory` готовность
локального SOCKS дополняется фиксированным alive-only warm-up delay (default 5 s,
timeout 30 s). Это не опрос состояния observatory и не доказательство готовности
его outbounds; первые циклы всё ещё могут отражать холодное состояние. Значения
настраиваются через `observatory_warmup_delay` и
`observatory_warmup_timeout`; `runtime_start_timeout` отдельно ограничивает
config-test, запуск процесса и SOCKS readiness. Такие профили следует
квалифицировать отдельным длительным real-Xray integration run до production.

## Health и диагностика

```console
curl --fail http://127.0.0.1:8080/health/live
curl --fail http://127.0.0.1:8080/health/ready
curl --fail http://127.0.0.1:8080/api/v1/status
curl --fail http://127.0.0.1:8080/metrics
docker compose logs --tail=200 prober
```

`live` проверяет основной цикл. `ready` означает принятую конфигурацию и
инициализированные scheduler/executor, но не доступность прокси и не наличие
первого success. Различайте:

| Состояние | Операционное значение |
| --- | --- |
| `unknown` | В текущем поколении ещё нет завершённого результата. |
| `failure` | Quorum не достигнут из-за сети/ожиданий ответа. |
| `error` | Исполнитель не смог корректно определить результат. |
| `stale` | Результат старше `max_result_age` либо загружен после перезапуска процесса и ещё не заменён новым циклом. |
| `disabled` | Check явно выключен. |

Не диагностируйте UUID, REALITY key или DNS-причину по одному общему SOCKS error:
точный reason публикуется только при надёжном сигнале. Сырые Xray stderr и
subscription URL не должны попадать в публичный лог.

Refresh сначала строит все включённые effective runtimes обновляемого source и
выполняет закреплённым Xray `run -test`; только затем публикуются generation и
LKG pointer. Config-test не проверяет сеть или credentials сервера. При ручном
identity reconciliation preview содержит revision, связанную с config,
generation, registry и полным candidate. Перед commit источник загружается
заново; несовпавшая revision отклоняет устаревший выбор и требует повторить
preview.

## Backup

Public `config export` не содержит секретов: semantic fingerprints пересчитываются
из строгого allow-list текущего LKG, а raw profile tags очищаются. Export также
содержит `expected_inventory`, но не заменяет backup. Для согласованной копии
остановите daemon или используйте snapshot storage, уважающий блокировку:

```console
docker compose stop prober
umask 077
mkdir -p backups
docker run --rm --read-only \
  -v xray-e2e-prober_prober-data:/data:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.21.3 \
  tar -C /data -czf /backup/prober-data.tgz .
docker compose start prober
```

Имя volume проверьте через `docker volume ls`; project name в compose зафиксирован
как `xray-e2e-prober`. Шифруйте архив и ограничивайте доступ как к credentials.

## Restore

Восстанавливайте в новый пустой volume при остановленном сервисе:

```console
docker compose down
docker volume create xray-e2e-prober_prober-data-restored
docker run --rm \
  -v xray-e2e-prober_prober-data-restored:/data \
  -v "$PWD/backups:/backup:ro" \
  alpine:3.21.3 \
  sh -c 'tar -C /data -xzf /backup/prober-data.tgz && chown -R 10001:10001 /data'
```

Затем укажите restored volume в временном Compose override, выполните
`prober config validate`, запустите сервис и проверьте ready/status. Не распаковывайте
недоверенный архив: tar path traversal и подмена profiles находятся вне threat
model этой команды.

## Обновление и rollback

1. Остановите scheduler и сделайте backup `/data`.
2. Прочитайте release notes и обновите `PROBER_IMAGE` на точный tag+digest.
3. Выполните `docker compose pull prober`.
4. На остановленном data volume запустите `docker compose run --rm prober config validate`.
5. Запустите `docker compose up -d prober`; проверьте `live`, `ready`, status и
   `synthetic_prober_config_last_reload_successful`.
6. Не объявляйте `unknown` нового поколения success. Дождитесь новых циклов.

Для rollback верните предыдущий image digest. Восстанавливайте backup только если
новая версия мигрировала state несовместимо; сначала сохраните аварийную копию
текущего состояния. Не смешивайте файлы двух поколений вручную.

## Resource limits и capacity

Значения Compose (`1 CPU`, `512 MiB`, `128 PID`, максимум 8 runtime в примере
конфигурации) — консервативные стартовые limits, а не capacity guarantee.

Короткий воспроизводимый замер выполнен 2026-09-05 на Linux/arm64-контейнере с
CPython 3.13.12 и Xray 26.3.27, `--network none --cpus 1 --memory 512m
--pids-limit 128`, после старта 1/4/8 managed VLESS RAW/TLS runtime. Каждая строка
— секундный idle sample без target requests; RSS является суммой текущих RSS, а
не уникальной памятью/peak RSS.

| Configs | Startup, s | Processes | Threads | Controller RSS, MiB | Xray RSS, MiB | Total RSS, MiB | Idle CPU, one core |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.205 | 2 | 9 | 35.83 | 27.63 | 63.46 | 0.00% |
| 4 | 0.306 | 5 | 31 | 35.83 | 111.64 | 147.46 | 0.00% |
| 8 | 0.745 | 9 | 59 | 35.83 | 223.03 | 258.86 | 0.00% |

Сценарий находится в [`benchmarks/runtime_resources.py`](../benchmarks/runtime_resources.py).
Пример повторного запуска с теми же ограничениями:

```console
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m --entrypoint python \
  -v "$PWD/benchmarks/runtime_resources.py:/benchmark.py:ro" \
  xray-e2e-prober:local /benchmark.py --sizes 1,4,8 --sample-seconds 1
```

Это подтверждает прохождение заявленных PID/RAM limits для idle-набора до восьми
процессов, но не является прогнозом production capacity. Перед production
измерьте выбранные transport/profile lifecycle под реальными target requests:
peak/unique RSS, CPU, queue delay, runtime start и HTTP duration. Persistent
profiles должны все помещаться в `max_active_runtimes`; scheduler не может молча
вытеснять их. При queue overflow увеличьте период/лимиты или уменьшите
concurrency — не трактуйте его как сетевую недоступность target.
