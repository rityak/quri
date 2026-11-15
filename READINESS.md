# quri · готовность к интеграции T-179

Статус: готов к внедрению в согласованном профиле. Приёмка 2026-11-15,
Go 1.26.7, Windows/Linux amd64. Предыдущая реализация — T-178 / D-018.

Граница проверки: самостоятельная библиотека, L4 streams/datagrams/control,
TLS 1.3 без early data, QUIC v1 и отдельный адаптер-контракт к miray. Публичный
inbound/outbound в конфиге ядра и production rollout сюда не входят.

Критерии завершения:

- Применимые требования RFC и известный GREASE defect проверены по коду и
  тестами; оставшиеся неприменимые возможности названы явно.
- Полные root/HTTP3 тесты используемого QUIC-форка проходят на целевых ОС;
  старые сбои устранены по механизму, не исключены из команд.
- Отмена, drain, ошибки потоков, UDP idle/expiry, malformed inputs и общие
  лимиты не допускают потери состояния, обхода политики и утечек ресурсов.
- Подтверждены caps TCP/UDP, одновременные данные/управление, restart,
  длительный обмен, независимый peer и Linux network impairment.
- Отдельный integration harness использует реальные miray outbound adapters
  для TCP/UDP; исходники ядра не меняются ради тестового встраивания.
- Фиксированы воспроизводимые версии зависимостей и wire contract; примеры,
  команды, бинарники и описание адаптера соответствуют проверенному коду.

## Результаты

T-181: проект, module/package, CLI, ALPN, docs и artifacts переименованы в
quri. Предыдущие generated binaries/archives/profiles и Go build/test/fuzz
caches очищены локально и на тестовом сервере. Новая сборка использует
`github.com/rityak/quri` и `quri/1`; backward aliases отсутствуют. Исторические
текстовые отчёты нормализованы под текущее имя, их замеры не повторялись.
Проверка после переименования и свежие артефакты — `T181-*.log`,
`quri-source-T181.tar.gz`, `SHA256SUMS` в `tools/artifacts/quri/`.
T-181 PASS: Windows standalone tests/vet/build, independent peer и miray
outbound harness; Linux те же suites под race, vet/build и 5 s smoke на
64 sessions через `QURI_SOAK`. Module identity обоих binaries проверена через
`go version -m`. Исходники, имена файлов и свежие artifacts проверены на
отсутствие прежних самостоятельных идентификаторов.

| Проверка | Фактический результат |
|---|---|
| Standalone SDK/CLI | `GOWORK=off go test ./...`, обычный `go vet ./...`, сборка Windows/Linux с published QUIC pin PASS; runtime не импортирует miray |
| Linux SDK race | Все пакеты PASS, включая реальные CLI-процессы, cancellation writer admission, partial-frame timeout и restart |
| QUIC fork | Полный `go test ./...` Windows и Linux PASS; полный Linux `-race ./...` PASS. В race-сборке пропускается только allocation assertion: race намеренно выбрасывает элементы sync.Pool; обычная проверка allocations включена |
| GREASE | Long-header parser всех v1 типов, unpacker AAD и non-QUIC multiplex integration PASS. TLS fixtures исправлены через ServerName, ICMP fixture закрывает transports; shutdown test ждёт входа в handler |
| TCP/UDP caps и память | 64 TCP + 32 UDP в одной сессии, отказ превышения, control при лимите и принудительный drain PASS. Учёт буферов возвращается к нулю; максимум control payload 1 MiB работает при UDP ceiling 8 MiB |
| Глобальная память | UDP ограничен 96 MiB при общем бюджете 128 MiB; rollback/release и сохранение control headroom проверены. Это учёт payload/control buffers, не RSS limiter |
| Soak/admission | 60 s, 64 authenticated sessions, 16 principals, 8 loopback IP, TCP + UDP + control; Windows PASS, Linux PASS, отдельно Linux race PASS. 65-й transport отвергнут. Это проверка при малых payload, не 64×96 полностью нагруженных flows |
| Restart/cleanup | Повторный bind того же server port, отказ старой сессии и новое применение конфигурации ровно один раз; forced drain при живых потоках PASS |
| UDP границы | Настоящие sockets: IPv4 0..65507 bytes, IPv6 0..65527 bytes, source endpoint и короткий read buffer; Windows/Linux race PASS |
| Независимый peer | Отдельный модуль upstream quic-go v0.64.1, собственный wire codec; Windows/Linux race PASS |
| Network impairment | Linux namespace: MTU1280, delay3±1ms, loss0.5%, duplicate0.1%, reorder1%; TCP half-close/recovery PASS. Namespace удалён; host routes/firewall не менялись |
| Реальный miray outbound | HY2/TLS, VLESS/TLS+XUDP, следующий quri; TCP response 77824 bytes после EOF, два UDP destinations и control, Windows/Linux race PASS. Исходники ядра не менялись |
| Fork sing | Race активности UDP устранён переносом решения sagernet/sing; полный Linux `go test -race ./...` PASS |
| Fork sing-quic | HY2 UDP write deadlines, reset deadline и close PASS, полный Linux `go test -race ./...` PASS |

В T-179 повторены три Linux fuzz targets по 3 s, два worker,
202587 executions без crash. Сырые generated logs этого этапа удалены при
очистке T-181; результаты сохранены в этой приёмке. Короткий прогон не
заменяет длительный fuzzing перед release.

## Закреплённые зависимости

| Fork | Published pin |
|---|---|
| quic-go | `v0.61.1-0.20261115102657-a6ba8bb51c89` |
| sing-quic, для miray harness | `v0.0.0-20261115102827-bd034150c9e2` |
| sing, для miray harness | `v0.5.9-0.20261115102824-a08acaf1b035` |

Все три commit опубликованы в наших forks. В production graph standalone
quri нужен только первый; два остальных закреплены в отдельном test-модуле.
TLS остаётся `metacubex/tls v0.1.9`; применимый аудит — [RFC-AUDIT.md](RFC-AUDIT.md).

## Перед встраиванием

Проверенный mapping и правила владения —
[mirayintegration/README.md](mirayintegration/README.md). Core checkout harness:
`ca3dd1ac673afa188bfb01fb48922262d9284136`. Основной `miray/go.mod` ещё не
обновляется: эти pins переносит изменение, которое зарегистрирует адаптер
в ядре. T-182: SDK выделен в [самостоятельный репозиторий](https://github.com/rityak/quri),
initial branch `main`; release tags пока не создавались.
Тестовые local replaces указывают только на SDK и core,
зависимости берутся по опубликованным версиям.

HY2 текущего ядра ограничивает UDP 4096 bytes, VLESS/XUDP не доставляет пустую
датаграмму; эти случаи проверены как ожидаемые потери на следующем транспорте.
Они не меняют гарантии нативного quri. Control имеет общий congestion window
с payload; гарантированной задержки при произвольном канале нет.

На Linux проверки шли последовательно в transient unit `MemoryMax=2G`,
`MemorySwapMax=0`, `OOMPolicy=continue`, `GOMAXPROCS=2`. Старый
`sing/common.Dup` даёт предупреждение analyzer `unsafeptr`; только vet для
integration graph запускается с `-unsafeptr=false`, остальные анализаторы
включены. Новых unsafe операций в T-179 нет. Standalone vet без исключений.

Артефакты родительского workspace: `tools/artifacts/quri/` — Windows/Linux
binaries, source archive, SHA256SUMS и свежие `T181-*.log`; в этот репозиторий
generated artifacts не включены. Исходные baseline
CPU/RSS/allocations T-178 — [VALIDATION.md](VALIDATION.md); после hardening
замеры производительности не повторялись. Продолжительные field/load tests,
формальная сертификация RFC и production rollout не входят в эту приёмку.
