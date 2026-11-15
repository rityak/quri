# RFC profile audit · T-179

Дата проверки: 2026-11-15. Профиль: L4 proxy, QUIC v1, TLS 1.3,
reliable byte streams, unreliable QUIC DATAGRAM и control stream `quri/1`.
Это проверка применимых механизмов по исходникам и тестам; сертификат полного
соответствия QUIC/TLS и криптографический аудит зависимостей не заявляются.

| Требование | Механизм и проверка |
|---|---|
| RFC 9293: ordered bytes, независимые FIN и abort | QUIC streams + явные `Stream.CloseWrite`/`CloseRead`. Ответ после EOF, read timeout с продолжением, loss/reorder/MTU recovery; half-close также через реальные HY2/VLESS/quri outbound |
| RFC 768/8085: отдельные unreliable messages | Каждая датаграмма сохраняет payload/endpoint; неполные fragments истекают, нет reliable fallback. Пустой payload и IPv4 65507/IPv6 65527 проверены до настоящего UDP socket; короткий read buffer потребляет сообщение с `io.ErrShortBuffer` |
| RFC 9000/9002: transport state, flow/congestion control | Используется QUIC fork без своей реализации ACK/loss/congestion. Отдельный control stream, ограниченные окна, no unidirectional streams, retry validation. Полные tests QUIC, включая recovery и transport lifecycle |
| RFC 9001: TLS в QUIC | TLS ≥1.3, проверка сертификата/имени и ALPN, handshake timeout. QUIC использует CRYPTO, собственную packet protection и key update; TLS record layer не передаётся |
| RFC 9221: negotiated DATAGRAM, без retransmit | Проверяется remote DATAGRAM support; emitted application fragments ≤1100 bytes. Очередь имеет cancellation/deadline/expiry и fairness с потоками. Тесты admission cancellation, expiry, legacy queue и packer anti-starvation |
| RFC 9287 §3: при объявленной поддержке принимать cleared fixed bit | Исправлены long-header parser и demux known connection IDs. Тесты Initial/0RTT/Handshake/Retry сохраняют исходные authenticated bytes; unpacker проверяет AAD, multiplex integration не отправляет GREASE в non-QUIC queue |
| RFC 1928: локальный SOCKS5 | CONNECT/UDP ASSOCIATE, domain/IPv6 addresses, источник UDP и lifetime по control TCP. Независимые клиенты и два CLI-процесса. SOCKS FRAG≠0 отбрасывается; это отдельно от внутренней fragmentation quri |
| RFC 8259: control JSON UTF-8 | Ограничение длины до allocation, invalid UTF-8 отклоняется, frame progress timeout, schema/version/namespace проверяются. Fuzz framing и malformed/replay tests |

## TLS 1.3 update и errata

[RFC 9846 §1.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-1.2)
заменил RFC 8446. Для закреплённого `metacubex/tls v0.1.9` сверены активные
пути `makeClientHello`, `key_schedule`, `handleNewSessionTicket` и QUIC
handshake. Новый ClientHello и server shared secret генерируют fresh key
material; кеша key shares в этих путях нет. Minimum TLS 1.3 задаёт quri.
ClientSessionCache отсутствует, server tickets отключены, early data запрещены;
PSK resumption/HRR-with-PSK не входит в профиль. Без resumption NST игнорируется.

TLS record-layer KeyUpdate/close_notify/user_canceled не применяются к QUIC
record layer: действуют RFC 9001 и transport close. Входящий TLS KeyUpdate
отвергается; `updatable_aead` проверяется тестами key phase/ACK, частых смен,
перестановки и смены ключей по packet limits. Это не тест на достижение
криптографического предела реальным многолетним трафиком.

Verified errata сверены с официальным `errata.json` и исходниками:

- RFC 9002 / 7539: RTT variance вычисляется по прежнему smoothed RTT,
  затем обновляется среднее (`internal/utils/rtt_stats.go`).
- RFC 9002 / 9169: пустые loss times не выбираются вместо ненулевых
  (`sent_packet_handler.getLossTimeAndSpace`).
- RFC 9000 / 7861: Retry token проверяет address/age; invalid Retry token
  обрабатывается отдельно от обычного NEW_TOKEN. Обычные server tests включены.
- RFC 9000 / 9281: packet number length увеличивается на границе half-window;
  fork всегда использует минимум два байта, `PacketNumberLengthForHeader`
  использует строгие `<` для границ 2/3 bytes.
- 6811 касается sequence number для `preferred_address`; quri этот параметр
  не задаёт. 8240/9272/9274 уточняют исключение CONNECTION_CLOSE из congestion control и текст
  header protection/registry, отдельного нового wire format не добавляют.
  9270 уточняет NewReno loss reduction; профиль использует CUBIC, не Reno.
- RFC 9846 / 9040: fallback TLS 1.2/1.0 не разрешён QUIC-профилем.
  RFC 1928 / 3198: IPv6 SOCKS UDP overhead — 22 bytes до payload.

Снимок статусов/IDs — [docs/standards-status.json](docs/standards-status.json).
Reported/Held errata не считаются принятой нормой.

## Границы

Исходные TCP headers, options, congestion control и исходный IP не туннелируются.
UDP options/IP surplus area из RFC 9868 также не переносятся. HTTP/3, MASQUE,
TUN/IP forwarding, QUIC v2, 0-RTT/resumption и preferred-address migration не
входят в этот профиль. Методика и результаты не доказывают максимальную
производительность, устойчивость против произвольного DoS или отсутствие
ошибок во всех зависимостях.
