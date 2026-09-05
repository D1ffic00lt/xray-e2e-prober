# Конфигурация

Основная конфигурация — YAML со строгой версионированной схемой. По умолчанию
контейнер читает `/data/config.yaml`, локальный процесс — путь из `PROBER_CONFIG`
или параметров CLI. Неизвестные поля отклоняются: опечатка не должна молча
менять маршрут проверки.

Перед запуском проверьте файл без применения:

```console
uv run --locked prober config validate
# либо для каталога Compose
docker compose run --rm prober config validate
```

Полный неинтерактивный пример с двумя сценариями находится в
[`examples/config.example.yaml`](../examples/config.example.yaml): HTTP VLESS
subscription и локальный JSON-массив полных профилей.

## Верхний уровень schema v1

| Поле | Тип | Назначение |
| --- | --- | --- |
| `schema_version` | `1` | Обязательная версия схемы. |
| `instance_id` | string | Стабильный ID точки наблюдения; не hostname scrape-реплики. |
| `sources` | list | Независимые HTTP/file/directory источники. |
| `target_sets` | list | Цели и quorum. |
| `assignments` | list | Индивидуальные и сохранённые правила назначения. |
| `egress_assertions` | list | Необязательные проверки IP выхода. |
| `default_target_set_ids` | list | Последний уровень назначения целей. |
| `scheduler` | object | Интервалы, таймауты и пределы параллельности. |
| `api` | object | Bind address и порт read-only API. |

Публичные ID имеют длину до 128 символов и состоят из букв, цифр и `_.:-`;
первый символ — буква или цифра. ID стабильны, имена предназначены только для
отображения. Credentials и их хеши не должны входить в ID.

Все значения времени в schema v1 задаются в секундах числом, например
`refresh_interval: 300` или `request_timeout: 15`.

## Источники

Минимальные поля источника:

```yaml
- source_id: primary-vless
  name: Primary subscription
  kind: http
  location_ref:
    file: /run/secrets/subscription-url
  format: auto
  target_set_ids: [internet-quorum]
  egress_assertion_ids: [office-egress]
  tags: [production]
```

`kind` принимает `http`, `file` или `directory`. `format` принимает `auto`,
`vless`, `vless_base64`, `xray_json` или `xray_json_array`. Для HTTP доступны:

| Поле | Default | Ограничение |
| --- | ---: | --- |
| `refresh_interval` | `300` | Больше 0. |
| `timeout` | `30` | Общий конечный timeout загрузки. |
| `max_bytes` | `4194304` | 1 byte–64 MiB. |
| `allow_empty` | `false` | При `false` пустой candidate отвергается. |
| `allow_insecure_http` | `false` | Для plain HTTP требуется явное `true`. |
| `enabled` | `true` | Отключает источник без удаления identity registry. |

`target_set_ids` и `egress_assertion_ids` — defaults источника, используемые,
когда запись не перехвачена индивидуальным или сохранённым assignment.
`tags` объединяются с тегами импортированной записи и доступны фильтру
assignment; это metadata, они не добавляются в Xray profile.

Укажите ровно одно из `location` и `location_ref`. URL subscription обычно
содержит токен, поэтому рекомендуется `location_ref`. Для локального пути без
секретов допустим `location`. HTTP authentication headers задаются по имени:

```yaml
headers_ref:
  Authorization:
    file: /run/secrets/subscription-authorization
  X-Tenant:
    env: PROBER_SOURCE_TENANT
```

`SecretRef` содержит ровно одно поле: `file` или `env`. Secret file содержит
только само значение; завершающий CR/LF удаляется. Не помещайте секреты в
`headers`, CLI arguments, labels или обычные переменные Compose-файла.

Источник публикуется атомарно. Перед заменой last-known-good (LKG) candidate
проходит fetch/parse/compatibility, компиляцию inventory и построение effective
config; каждый уникальный включённый runtime этого источника проверяется
закреплённым Xray через `run -test`. Ошибка любого такого этапа оставляет прежний
LKG. Это синтаксическая/config проверка, не сетевой handshake: валидная новая
конфигурация с неверными credentials подключения принимается и должна дать
неуспешную E2E-проверку, а не скрываться старым маршрутом.

`allow_empty: true` — осознанно опасное исключение: пустой HTTP/file candidate
или каталог без поддерживаемых `.json`, `.txt`, `.conf` файлов считается
валидным и удаляет все entries источника. При `false` тот же candidate
отклоняется с сохранением LKG. Лимит `max_bytes` применяется и к суммарному
размеру документов каталога.

## Цели и quorum

Набор содержит хотя бы одну цель и целый `quorum` от 1 до числа включённых целей:

```yaml
target_sets:
  - target_set_id: internet-quorum
    name: Internet reachability
    quorum: 2
    targets:
      - target_id: application-health
        name: Application health
        url: https://service.example/health
        method: GET
        expected_statuses: [200, 204]
        timeout: 10
        body:
          kind: regex
          value: '^(ok|healthy)$'
        max_body_bytes: 65536
        follow_redirects: false
        max_redirects: 0
```

Метод MVP — только `GET`. Проверка body бывает `exact` или `regex`; чтение
ограничено `max_body_bytes`. Redirect по умолчанию запрещён. При включении
`follow_redirects` задайте `max_redirects` (если оставить 0, валидатор schema v1
применит 5). Все переходы обязаны идти через тот же Xray runtime.

Все цели цикла выполняются даже после достижения quorum. Итог набора строится
только из одного завершённого цикла одного поколения. Публичные домены в примере
редактируемы и не считаются автоматически независимыми сетями; для надёжного
мониторинга выберите цели с известными владельцами и failure domains.

## Назначения и приоритет

Для каждой импортированной записи применяется ровно следующий порядок:

1. Индивидуальное правило с `entry_id`.
2. Первое подходящее сохранённое правило в порядке `assignments`.
3. `source.target_set_ids`, `source.egress_assertion_ids` и состояние source.
4. `default_target_set_ids`.

Правило задаёт полный итог (`enabled`, `target_set_ids` и
`egress_assertion_ids`), а не частичное добавление. Фильтр поддерживает
`name_glob`, `name_regex`, `protocol`, `transport` и `tags`; `source_id`
задаётся рядом с `filter`. Новые entries будущих refresh также попадают под
сохранённые фильтры.

`name_regex` ограничен безопасным линейным подмножеством длиной до 256
символов: литералы, `.`, классы символов (`[a-z]`), `^`/`$`, до 32 плоских
альтернатив и необязательный начальный `(?i)`. Внешняя группа разрешена, поэтому
`(?i)(retired|disabled)` поддерживается. Повторы (`*`, `+`, `?`, `{m,n}`),
вложенные группы, lookaround и backreference отклоняются при валидации
конфигурации. Для wildcard-сопоставления используйте `name_glob` с синтаксисом
shell (`*`, `?`, `[abc]`), например `name_glob: "*-disabled"`.

```yaml
assignments:
  - assignment_id: disable-one-entry
    entry_id: ent_stable_id
    enabled: false
    target_set_ids: []

  - assignment_id: all-xhttp-from-primary
    source_id: primary-vless
    filter:
      protocol: vless
      transport: xhttp
    enabled: true
    mode: connection
    target_set_ids: [internet-quorum]
    egress_assertion_ids: [office-egress]
```

Для полного JSON-профиля `mode: profile` сохраняет исходную routing semantics.
Для проверки конкретного VLESS outbound используйте `mode: connection` и при
неоднозначности `outbound_tag`. Эти режимы создают разные checks. Для такого
правила `selection_id` по умолчанию равен `assignment_id`: именно он, а не
source-controlled текст inbound/outbound tag, участвует в стабильном `check_id`.
Обычно задавать `selection_id` вручную не требуется; export v2 материализует его
до очистки приватных tag selectors.

## Egress assertions

```yaml
egress_assertions:
  - assertion_id: office-egress
    name: Office ranges
    url: https://echo.example/ip
    expected_cidrs: [203.0.113.0/24, '2001:db8:1234::/48']
    response_format: json
    json_field: ip
    timeout: 10
    enabled: true
```

Поддерживаются `plain` (один IPv4/IPv6) и `json` с обязательным `json_field`.
Замените documentation ranges собственными CIDR. `mismatch` означает только то,
что запрос к конкретному echo endpoint вышел с неожиданного IP; это не доказывает
маршрут остальных targets. Ошибка/невалидный ответ дают `error`/`unknown`, а не
ложный `mismatch`.

## Scheduler и API

```yaml
scheduler:
  interval: 60
  request_timeout: 15
  runtime_start_timeout: 10
  runtime_restart_backoff_initial: 1
  runtime_restart_backoff_max: 60
  observatory_warmup_delay: 5
  observatory_warmup_timeout: 30
  max_active_runtimes: 8
  max_parallel_requests: 32
  max_queue_size: 1024
  max_result_age: 180
api:
  host: 127.0.0.1
  port: 8080
```

`max_active_runtimes` должен вмещать все persistent profiles. Они не должны
молча вытесняться. Переполнение `max_queue_size` относится к scheduler error, а
не к network failure. `max_result_age` определяет переход результата в `stale`;
согласуйте его с freshness window в Prometheus rules.

После ошибки старта или неожиданного завершения persistent runtime повторный
старт ограничивает exponential backoff: от
`runtime_restart_backoff_initial` до `runtime_restart_backoff_max`. Значение
initial `0` фактически отключает задержку. Успешный fresh start сбрасывает его
сразу; persistent runtime — после того, как наблюдался живым в течение окна
стабильности. Backoff привязан к effective runtime и generation, поэтому новая
generation не наследует старую задержку.

Для profile с top-level `observatory` или `burstObservatory` после готовности
локального SOCKS выполняется фиксированная задержка
`observatory_warmup_delay`, ограниченная
`observatory_warmup_timeout`. В течение неё проверяется, что child process жив.
Это не запрос статуса observatory и не гарантия здоровья его outbounds. Delay
может быть `0`, timeout обязан быть положительным и не меньше delay.

Runtime-каталог не является полем schema: он задаётся отдельно переменной
`PROBER_RUNTIME_DIR`. Compose направляет его в ограниченный `tmpfs /tmp`, а
нативный запуск без переменной использует process-private temporary directory.
Текущие последствия и операционные меры описаны в
[эксплуатации](operations.md#runtime-файлы-и-ограничения-перезапуска).

На хосте безопасный bind — `127.0.0.1`. В Compose процесс слушает `0.0.0.0`
только внутри контейнера, а port mapping всё равно привязан к loopback хоста.

## Изменение и экспорт

При работающем демоне изменения должны идти через локальный управляющий Unix
socket; при остановленном — под блокировкой каталога данных. Не редактируйте
runtime state вручную. Команды:

```console
prober config validate
prober config export
```

Export переносит конфигурацию, opaque `entry_id` и пересчитанный по строгому
allow-list `connection_fingerprint`. В fingerprint входят только тип транспорта,
security и несекретные параметры endpoint; UUID, ключи, short ID, XHTTP path,
`external_id`, `name_key`, raw inbound/outbound tags и их хеши туда не входят.
Сохранённое в registry значение export не копирует: оно заново вычисляется из
текущего LKG. Это позволяет другой точке с тем же source однозначно восстановить
`entry_id` после подстановки собственных credentials. Неоднозначные записи, как
и раньше, требуют `entries reconcile`.

Bundle также содержит `expected_inventory`: список source/check ID, вычисленный
из текущих LKG, с `mode`, `target_set_id` и флагом `enabled`. Его можно использовать
как исходные данные для независимого inventory Prometheus. На новой точке задайте
собственный `instance_id`, восстановите `identity_registry`, заполните secret refs
и повторно укажите очищенные tag selectors. `check_id` остаётся одинаковым между
точками: выбранный маршрут идентифицируется стабильным `assignment_id`, а не
текстом profile tag.

Export по-прежнему не заменяет state backup. Резервная копия всего `/data`
секретна, в отличие от публичного export.
