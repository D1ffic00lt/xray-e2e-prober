# Матрица совместимости

Эта матрица — явная граница prober `0.1.x`, а не перечень возможностей бинарника
Xray. Всё, чего нет в таблице, считается неподдерживаемым и должно отклоняться до
запуска runtime. Неизвестный значимый параметр VLESS URI нельзя молча удалить.

Автоматизированный набор включает unit/fake-Xray сценарии и opt-in real-Xray
client/server matrix в `tests/integration/test_real_xray.py`. Matrix целиком
работает внутри одного контейнера без внешней сети: HTTP origins, VLESS server,
REALITY camouflage endpoint и managed SOCKS clients слушают только локальные
сокеты. В CI она запускается для Linux amd64 и arm64 с закреплённым Xray.

## Закреплённая среда

| Компонент | Версия | Проверка |
| --- | --- | --- |
| CPython | 3.13.12 | Base image index digest `sha256:a58daefb…de12b6`. |
| Xray Core | 26.3.27 | Архивы amd64/arm64 проверяются SHA-256 в Dockerfile. |
| uv | 0.12.5 | Установка версии + `uv sync/run --locked`. |
| Prometheus/promtool | 3.5.0 | CI image закреплён manifest digest. |

Xray обновляется только отдельным изменением version, обоих checksums и матрицы
тестов. Автоматической загрузки Core или geo-data при старте нет. В образ входят
`geoip.dat` и `geosite.dat` из того же Xray release archive.

## Источники и форматы

| Вход | Граница MVP | Примечание |
| --- | --- | --- |
| HTTPS subscription | Да | Ограничены timeout, redirect и размер; auth headers не переходят на другой origin. |
| HTTP subscription | Только opt-in | Требуется `allow_insecure_http: true`. |
| Локальный файл | Да | Читается с конечным лимитом размера. |
| Локальный каталог | Да | `.json`, `.txt`, `.conf`; общий size limit, атомарный candidate. Пустой каталог принимается только при `allow_empty: true`. |
| VLESS URI, одна строка на запись | Да | Неизвестные влияющие параметры отклоняются. |
| Base64 списка VLESS | Да | После bounded decode проверяется фактическое содержимое. |
| Полный Xray JSON object | Да | Объект сохраняется без потери неизвестных полей. |
| JSON array полных profiles | Да | Каждый объект — отдельная импортированная запись. |
| HTML, Clash/YAML, VMess/Trojan/SS subscription | Нет | Понятная `source_parse`/`unsupported`, без best-effort угадывания. |

В закреплённом Xray 26.3.27 поле `tlsSettings.allowInsecure` удалено. Поэтому
`allowInsecure=false`/`insecure=false` в старых VLESS URI принимается как
эквивалент строгого значения по умолчанию, но удалённое поле в effective config
не переносится. Значение `true` и наличие `allowInsecure` в полном JSON-профиле
отклоняются как `unsupported`; запрос на отключение проверки сертификата нельзя
молча изменить. Для частных CA используется системное доверие или certificate
pinning, поддерживаемое закреплённой версией Xray.

## Режим `connection`

| Selected outbound | Transport | Security | Статус границы |
| --- | --- | --- | --- |
| VLESS | RAW/TCP | TLS | Да; real-Xray client/server fixture. |
| VLESS | RAW/TCP | REALITY | Да; real-Xray client/server fixture. |
| VLESS | XHTTP | TLS | Да; real-Xray fixture для Xray 26.3.27. |
| VLESS | XHTTP | REALITY | Да; real-Xray fixture для Xray 26.3.27. |
| VMess, Trojan, Shadowsocks и прочие | Любой | Любая | Не поддерживается. |

Effective config содержит один приватный SOCKS inbound, выбранный VLESS outbound
и только его явные `proxySettings`/`dialerProxy` зависимости. Catch-all routing
направляет прикладной запрос в selected outbound. Исходный direct/fallback не
может превратить падение выбранного подключения в success. Lifecycle по
умолчанию `fresh`: новый Xray и новый HTTP pool на каждый цикл набора.

## Режим `profile`

| Возможность профиля | Статус | Условие |
| --- | --- | --- |
| Outbounds `vless`, `freedom`, `blackhole`, `dns` | Ограниченно поддерживается | Другой protocol отклоняет весь profile. |
| Сохранение порядка outbounds и routing | Да | Не меняется ради «успешного» запуска. |
| Domain/IP/port/network/inboundTag rules | Да | Выбранный inbound моделируется локальным SOCKS с сохранением tag/sniffing. |
| Несколько inbounds | Только явный выбор | Без однозначного выбранного inbound profile отклоняется. |
| `balancers`, `observatory`, `burstObservatory` | Ограниченно, persistent | Real fixture покрывает `observatory` + одноэлементный `leastPing` balancer и fixed alive-delay. Нет observatory health signal; multi-outbound failover и `burstObservatory` не квалифицированы. |
| DNS и routing resources | Только доступные | Встроенные geo-data есть; прочие файлы монтируются явно. |
| `source`, `sourcePort`, `user`, `attrs`, process rules | Нет | Исходные сведения SOCKS-сценарию недоступны. |
| TUN/transparent proxy, interface, packet mark, tproxy | Нет | Нужны OS state или дополнительные privileges. |
| Imported `api`, `metrics`, `reverse`, публичные listeners | Нет | Отклоняются как небезопасные функции. |
| Произвольные callbacks/webhooks и фоновые actions | Нет | Автоматически не исполняются. |

Profile lifecycle по умолчанию `persistent`: это проверка поведения работающего
профиля, включая накопленное состояние balancer/observatory. Прямой результат
`success` допустим, если его выбрал исходный routing. Он подтверждает доступность
URL через профиль, но не конкретный VLESS outbound или серверный inbound. Первый
цикл может отражать холодное состояние: fixed warm-up проверяет только, что Xray
остаётся жив в течение заданной задержки, и не является observatory сигналом
готовности.

До публикации нового LKG prober строит effective config каждого уникального
включённого runtime обновляемого source и вызывает закреплённый Xray `run -test`.
Это отсекает несовместимую конфигурацию, но не заменяет сетевой handshake и не
расширяет заявленную здесь fixture coverage.

## HTTP и egress semantics

- Назначение передаётся Xray как домен через SOCKS; приложение не выполняет
  предварительный resolve цели. TLS SNI и HTTP Host соответствуют target URL.
- Probe client обязан использовать явный SOCKS proxy и `trust_env=False`.
  Переменные `HTTP_PROXY`/`HTTPS_PROXY` не создают обход.
- Target поддерживает GET, status set, bounded exact/regex body и явную redirect
  policy. Все redirects идут через тот же runtime.
- Egress endpoint поддерживает один plain IP либо JSON field, IPv4 и IPv6.
  Результаты reachability и egress независимы.
- `success/failure`, `unknown`, `error`, `stale`, `disabled` не взаимозаменяемы;
  scheduler/runtime error не публикуется как сетевой failure.

## Как квалифицировать релиз

Real matrix проверяет закреплённую версию Core, все четыре RAW/XHTTP ×
TLS/REALITY комбинации, неверные UUID/REALITY key, profile routing между direct и
VLESS, отсутствие direct/fallback bypass в connection mode, egress IP через
реальный VLESS hop, fresh runtime после смены credentials и persistent
одноэлементный `leastPing` profile после fixed alive-delay. Источник выбранного
маршрута различается адресами `127.0.0.1` и `127.0.0.2`, поэтому эти проверки не
основаны только на чтении generated config.

Воспроизводимый запуск той же matrix:

```console
docker build --target integration-test -t xray-e2e-prober:integration .
docker run --rm --network none \
  --add-host xray-integration.invalid:127.0.0.1 \
  -e XRAY_TEST_SERVER_HOST=xray-integration.invalid \
  xray-e2e-prober:integration
```

Обычный unit suite:

```console
uv run --locked pytest
```

Обе команды необходимы для заявленной матрицы. Они не квалифицируют
multi-outbound observatory failover, `burstObservatory`, отдельный authoritative
DNS server или HTTPS application target; такие строки расширяются только вместе
с детерминированными fixtures и обновлением этой таблицы.
