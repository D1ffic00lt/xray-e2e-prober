# Xray E2E Prober

Самостоятельный сервис для end-to-end проверки клиентских подключений Xray.
Prober импортирует VLESS-подписки или полные JSON-профили, выполняет HTTP(S)
запросы через локальный SOCKS-вход Xray и публикует безопасные результаты через
CLI, read-only HTTP API и Prometheus-метрики.

> Статус: ранний MVP `0.1.1`. Помимо локальных SOCKS/HTTP fixtures и subprocess
> lifecycle scenarios, opt-in Docker integration suite запускает закреплённый
> Xray Core `26.3.27` в локальной client/server matrix: VLESS RAW и XHTTP с TLS
> и REALITY, включая негативные проверки UUID и REALITY key. Точные границы
> описаны в [матрице совместимости](docs/compatibility.md); перед production всё
> равно нужен приёмочный прогон конкретного образа и измерение ресурсов.

Проверка `success` означает достижение quorum через исполняемый профиль или
выбранное подключение и совпадение всех назначенных включённых egress assertions.
Это не ICMP/TCP probe. В режиме `profile` прямой выход и fallback допустимы, если
так задан исходный routing; такой результат не доказывает здоровье каждого VLESS
outbound. Географию выхода сервис не угадывает: для этого нужна явно настроенная
egress assertion с ожидаемыми CIDR.

## Быстрый запуск в Docker

Требуются Docker Engine и Docker Compose v2. Из исходников собирается фиксированный
локальный тег `xray-e2e-prober:0.1.1`; в образ входят CPython 3.13.12 и Xray Core
26.3.27. Во время старта пакеты не скачиваются.

```console
docker compose build
docker compose run --rm prober setup --data-dir /data
docker compose up -d prober
curl --fail http://127.0.0.1:8080/health/ready
docker compose exec prober prober status
```

Мастер сохраняет настройки и секреты в тот же именованный volume, который затем
использует демон. HTTP API публикуется только на `127.0.0.1` хоста; локальные
SOCKS-порты Xray и управляющий Unix socket наружу не публикуются.

Для опубликованного образа задайте точный release tag с manifest digest, не
`latest`:

```console
export PROBER_IMAGE='ghcr.io/REPLACE_OWNER/xray-e2e-prober:0.1.1@sha256:REPLACE_DIGEST'
docker compose pull prober
docker compose up -d prober
```

Значения `REPLACE_*` намеренно не являются рабочими: этот репозиторий не выдаёт
несуществующий опубликованный образ за доступный. Инструкция публикации и
обновления находится в [docs/operations.md](docs/operations.md).

## Локальная разработка

Версия Python задаётся `.python-version`, зависимости — `uv.lock`. Lock-файл
проверяется, но не обновляется следующими командами:

```console
uv sync --locked --all-groups
uv run --locked prober setup --data-dir ./data
uv run --locked prober serve --data-dir ./data --host 127.0.0.1 --port 8080
uv run --locked pytest
```

Правила Prometheus проверяются отдельно закреплённым `promtool`; готовые команды
есть в [examples/prometheus/README.md](examples/prometheus/README.md). CI выполняет
оба набора проверок с `uv --locked`.

Real-Xray matrix из `tests/integration/test_real_xray.py` запускается отдельно и
не использует публичную сеть:

```console
docker build --target integration-test --tag xray-e2e-prober:integration .
docker run --rm --network none \
  --add-host xray-integration.invalid:127.0.0.1 \
  --env XRAY_TEST_SERVER_HOST=xray-integration.invalid \
  xray-e2e-prober:integration
```

## CLI и коды завершения

CLI покрывает setup, управление источниками, целями, egress assertions и
назначениями, ручной запуск checks, status и validate/export конфигурации. Для
автоматизации используйте `--json`, а
для проверки — явный one-shot вызов:

```console
uv run --locked prober check run --once --json
```

`check run` возвращает `0` при полном успехе, `1` при подтверждённом failure или
egress mismatch и `2` при ошибке/неполном результате. Полный перечень команд,
опций, JSON-режимов и общих кодов завершения находится в
[docs/cli.md](docs/cli.md).

## Публичные endpoints

- `GET /health/live` — жив основной цикл процесса.
- `GET /health/ready` — конфигурация принята, scheduler и executor готовы.
- `GET /api/v1/status` — экземпляр, источники и очередь.
- `GET /api/v1/checks` и `/api/v1/checks/{check_id}` — актуальные результаты.
- `GET /metrics` — Prometheus exposition.

Readiness не зависит от доступности проверяемых прокси. До первого завершённого
цикла check корректно остаётся `unknown`; `failure`, `error` и `stale` имеют
разный смысл. Сохранённый результат после перезапуска процесса принудительно
публикуется как `stale` до нового цикла, даже если его возраст меньше
`max_result_age`.

## Документация

- [CLI](docs/cli.md) — все команды, режимы вывода и коды завершения.
- [Конфигурация](docs/configuration.md) — schema v1, секреты, цели и приоритеты.
- [Совместимость](docs/compatibility.md) — точные границы импортёров и profile.
- [Эксплуатация](docs/operations.md) — hardening, backup/restore и обновление.
- [Неинтерактивный пример](examples/config.example.yaml).
- [Recording/alert rules](examples/prometheus/README.md) — необязательная
  интеграция; Prometheus не нужен для работы сервиса.

## Не входит в MVP

Web UI, многопользовательская авторизация, встроенная рассылка, центральная БД,
кластерный координатор, создание серверных inbound, Docker socket, Kubernetes и
зависимость от какой-либо панели. Развёртывание не меняет существующий мониторинг
и не перенастраивает сторонние контейнеры.
