# quri/1 · формат и состояния

Версия: 1. Дата: 2026-11-15. Это собственная прикладная спецификация поверх
QUIC v1/RFC 9000–9002 и DATAGRAM/RFC 9221. Совместимость с GNS/qd не требуется.
Поля integer имеют network byte order. JSON — UTF-8, byte payload в JSON
представляется base64 по правилам Go encoding/json. Отправитель не выдаёт
дубликаты JSON-ключей. Неизвестные JSON-поля принимаются по поведению
encoding/json; обязательные новые возможности требуют новой согласованной
версии протокола, а не скрытого JSON-параметра.

## Соединение

ALPN `quri/1`, только QUIC v1, TLS 1.3, DATAGRAM обязателен. 0-RTT выключен,
unidirectional streams запрещены. Клиент не разрешает server-initiated bidi
streams; сервер использует существующий control stream для своих сообщений.

Состояния: TLS → Hello → authenticated → configured → draining → closed.
Handshake/Hello и Open имеют timeout 5 s. Keepalive 15 s, QUIC idle 45 s.
Control request ограничен 5 s, drain — 10 s, включая ожидание writer admission;
более ранний context deadline имеет приоритет. После первого байта control
frame его header и body должны поступить за 5 s; idle control stream разрешён.
Сервер применяет Retry/address validation, до 64 transport connections,
до 8 на source IP и до 4 аутентифицированных сеансов на principal.

Первый client bidi stream (ID 0) — control. Начальный Hello:

```json
{"version":1,"token":"<individual secret, 32..256 bytes>","udp":true}
```

Hello и ответ начинаются с uint32 длины JSON, не более 4096 bytes. Успех —
`{}`, отказ — объект с `error` либо закрытие соединения. Peer обязан проверить
успех и transport DATAGRAM support. Сертификат сервера/имя проверяются до
application authentication. Token не заменяет TLS server authentication.

## Control

После Hello каждый frame имеет header:

| Bytes | Поле |
|---|---|
| 0 | kind, uint8 |
| 1..8 | request ID, uint64, ненулевой |
| 9..12 | JSON body length, uint32 |
| 13.. | JSON body |

Kind 1 — configuration, 2 — application message, 3 — drain.
Response имеет `kind | 0x80` и тот же ID; тип ответа должен совпадать с
ожидаемым. Неизвестный request kind с битом `0x40` игнорируется с пустым
успешным ответом; без этого бита возвращается ошибка unsupported request.
Framing failure/конфликт ID закрывает соединение.

Request body: `{"namespace":"...","version":1,"payload":"<base64>"}`.
Namespace 1..128 bytes, version ненулевая; decoded payload не более 1 MiB.
Body cap — `4 * ceil(1 MiB / 3) + 1024` bytes с учётом base64/JSON.
Drain body — пустой Request; его schema-поля не используются.
Response: `error` (string), `code` (string), `handle` (uint64), `payload` (base64), поля могут
отсутствовать. Наличие непустого error означает отказ; text не раскрывает
секреты или содержимое outbound config.

Flow errors различают `denied`, `refused`, `unreachable`, `timeout`, `limit`,
`protocol`, `draining`. Клиент возвращает `RemoteError`; `errors.Is` сохраняет
основные категории. SOCKS5 использует REP 2 для policy denial, 5 для connection
refusal, 4 для недоступного назначения, 1 для внутреннего/ресурсного отказа.

ID монотонно возрастают независимо в каждом направлении. Есть один активный
исходящий request на сторону. Получатель кеширует до 16 результатов, суммарно
до 2 MiB. Повтор кешированного ID с тем же kind/body возвращает прежний ответ;
с другим содержимым закрывает соединение. ID не выше high-water mark,
результат которого уже вытеснен, получает отказ без повторного применения.
Новые ID продолжают обслуживаться: это bounded replay window, не лимит
числа сообщений за жизнь соединения. Автоматических retry нет.

Configuration проверяется host callback. Успешный первый запрос возвращает
handle 1, связанный только с данным сеансом. Второй новый configuration request
отклоняется. Старый replay не создаёт новый маршрут. До принятия handle новые
flows отклоняются; fallback отсутствует. Standalone принимает только namespace
`direct`, version 1, decoded payload `{}`. Серверная CIDR-политика клиентом
не изменяется. Across crash/reconnect exactly-once не обеспечивается: внешние
side effects требуют host idempotency.

## TCP и UDP associations

Каждый flow использует отдельный client bidi stream, начинающийся с uint32
длины и Open JSON, не более 4096 bytes:

```json
{"kind":"tcp","handle":1,"address":"example.org:443"}
```

Для UDP kind `udp`, address не используется: destination передаётся в каждом
сообщении. Ответ — length-prefixed response JSON. После TCP Accept идут сырые
байты. FIN отображается в half-close, reset — в ошибку. Полный Close без
CloseWrite прерывает незавершённую отправку; после штатного CloseWrite уже
очередной FIN не заменяется reset при освобождении локального объекта.

UDP association ID равен StreamID её Open stream. После ответа data bytes
в этом stream не используются; FIN/reset/закрытие stream завершают ассоциацию.
При отсутствии трафика в обоих направлениях server relay имеет idle timeout
60 s. Непрерывная односторонняя отправка сохраняет ассоциацию без ответов.
Peer должен закрывать ассоциации явно после использования.

Лимиты: 64 TCP flows и 32 UDP associations на сеанс. Входящие Open handlers
также ограничены. Предельное QUIC receive window каждого stream — 64 KiB;
connection receive window — 8 MiB. Они ограничивают конкуренцию данных и
оставляют запас для control stream, но не резервируют полосу сети.

## DATAGRAM

Один QUIC DATAGRAM переносит один фрагмент. Header:

| Bytes | Поле |
|---|---|
| 0..7 | association ID, uint64 |
| 8..15 | message ID, uint64, ненулевой |
| 16..17 | decoded total payload length, uint16 |
| 18..19 | fragment payload offset, uint16 |
| 20..21 | endpoint string length, uint16 |
| 22 | fragment index, uint8, zero-based |
| 23 | fragment count, uint8, 1..64 |
| 24.. | endpoint, затем fragment payload |

Endpoint вида `host:port`/`[IPv6]:port`, не более 260 bytes, без zone ID;
port 1..65535. Только фрагмент 0 содержит endpoint и имеет offset 0; у других
endpoint length равен нулю. Текущий отправитель ограничивает DATAGRAM payload
1100 bytes; первый фрагмент содержит меньше данных из-за endpoint.
Нулевое UDP-сообщение передаётся одним фрагментом с total=0.

Message IDs возрастают на ассоциацию. Проверяются count/total, пересечения,
индексы и согласованность дубликатов; доставка производится только после
полной сборки и проверки всех байтов. Total не более 65527, IPv4 endpoint
ограничен 65507. Максимум 32 неполных сообщения и 1 MiB сборки на сеанс;
срок сборки 300 ms от первого фрагмента. Потерянный фрагмент теряет сообщение
целиком. Последние 128 completed IDs хранятся до 1 s для подавления дублей;
за пределами окна отсутствие повторной доставки не гарантируется, как и у UDP.

Входная очередь — 16 полных сообщений на ассоциацию с drop-new при заполнении.
Retained UDP payload buffers ограничены 8 MiB/сеанс и 96 MiB/server process;
вместе с control frame и replay cache — 16 MiB/сеанс и 128 MiB/server process.
UDP не занимает оставшиеся 8 MiB/сеанс и 32 MiB/process для control. Это
не резерв отдельного maximum-size request одновременно всем 64 клиентам.
Учёт не является
ограничителем RSS или общих расходов runtime/QUIC/kernel.

WriteTo имеет deadline не позже 100 ms с момента вызова, включая ожидание
очереди ассоциации. Более ранний пользовательский deadline действует также.
Смена deadline прерывает заблокированную операцию. QUIC queue отбрасывает
просроченные фрагменты перед упаковкой; контекст ограничивает admission.
Уже упакованный/переданный в socket send queue пакет не отзывается.
DATAGRAM не переводится в reliable stream и не retransmit-ится.

## Завершение

Shutdown помечает локальную сторону draining, запрещает новые Open и ждёт
завершения локальных flows. Затем drain request заставляет peer также дождаться
своих flows. Полученный response подтверждает готовность peer к закрытию.
По deadline — явная ошибка и abort. Немедленный Close не обещает drain.

TCP completion означает EOF/CloseRead плюс CloseWrite либо полный Close.
Пользователь библиотеки должен дочитать ответ и освободить ассоциации.
Потоки после reconnect не возобновляются, старые handles не переносятся.

## Независимые vectors

Length-prefixed bytes `abc`: `00000003616263`.

Configuration frame, ID 7, body `{}`:
`010000000000000007000000027b7d` (framing vector, не валидный application schema).

UDP association 4, message 1, payload `abc`, endpoint `127.0.0.1:9`:
`0000000000000004000000000000000100030000000b00013132372e302e302e313a39616263`.

Vectors проверяются отдельно от end-to-end тестов. Test-модуль `interop/`
кодирует Hello/config/Open/DATAGRAM независимо и использует upstream QUIC.
