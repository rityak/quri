# quri

Имя Go-модуля — `github.com/rityak/quri`, CLI — `quri`, ALPN — `quri/1`.

Самостоятельная Go-библиотека и клиент/сервер для TCP, UDP и типизированного
служебного обмена поверх QUIC v1. Ядро miray не требуется. Формат —
[PROTOCOL.md](PROTOCOL.md), применимый RFC-профиль — [RFC-AUDIT.md](RFC-AUDIT.md),
готовность и проверки — [READINESS.md](READINESS.md).

## Возможности

- TCP: отдельный bidi stream, реальные deadlines, half-close и передача reset.
- UDP: адреса IPv4/IPv6/domain, нулевые payload, ненадёжная фрагментация до
  65527 bytes (IPv4 — до 65507), bounded reassembly, без reliable fallback.
- Отдельный надёжный control stream; служебные сообщения в обе стороны,
  версия прикладной схемы, replay cache и защита от повторного применения.
- TLS с проверкой сервера, индивидуальные tokens; 0-RTT выключен.
- Неизменяемый маршрут на сеанс через host callbacks. Standalone разрешает
  только direct route к адресам из явного CIDR allowlist.
- Локальный SOCKS5 CONNECT/UDP ASSOCIATE, конфигурация JSON, остановка по сигналу.

Используется наш `rityak/quic-go`, pin:
`v0.61.1-0.20261115102657-a6ba8bb51c89`. Импорты сохраняют имя
`github.com/metacubex/quic-go`. Копирования кода GNS/qd нет.

Go не наследует `replace` зависимого модуля. Приложение, импортирующее quri,
должно закрепить ту же замену в собственном `go.mod`; будущий адаптер miray
обновит pin ядра при интеграции:

```go
replace github.com/metacubex/quic-go => github.com/rityak/quic-go v0.61.1-0.20261115102657-a6ba8bb51c89
```

## Сборка и проверки

Проверено Go 1.26.7, Windows/Linux amd64. Директива `go 1.20` сохраняет
совместимость языка с miray; запуск на старом toolchain отдельно не проверен.

```sh
git clone https://github.com/rityak/quri.git
cd quri
go build -trimpath ./cmd/quri
go test ./...
go vet ./...
```

На Linux дополнительно `go test -race ./...`. Независимый клиент на upstream
QUIC находится в отдельном test-модуле, чтобы не добавлять второй транспорт
в зависимости приложения:

```sh
cd interop
go test ./...
```

## Локальный запуск

В `examples/` — два JSON-шаблона с пустыми tokens: без настройки они не
запускаются. Нужен сертификат с SAN имени сервера и одинаковый случайный token
в обеих конфигурациях. Для локального теста можно создать сертификат OpenSSL:

```sh
openssl req -x509 -newkey ed25519 -nodes -days 30 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout examples/server-key.pem -out examples/server.pem
```

Подготовка конфигураций в PowerShell; Python нужен только для этого примера:

```powershell
Copy-Item examples/server.json examples/server.local.json
Copy-Item examples/client.json examples/client.local.json
python -c "import json,secrets,pathlib; token=secrets.token_hex(32); [p.write_text(json.dumps(dict(json.loads(p.read_text()),token=token),indent=2),encoding='utf-8') for p in map(pathlib.Path,['examples/server.local.json','examples/client.local.json'])]"
```

Секреты находятся в файлах, доступ к которым должен иметь только владелец.
Файлы `*.local.json` и PEM в `examples/` исключены из Git. Пути CA/cert/key
разрешаются относительно файла конфигурации.

В двух терминалах из каталога модуля:

```sh
go run ./cmd/quri -config examples/server.local.json
go run ./cmd/quri -config examples/client.local.json
```

Клиент слушает SOCKS5 на `127.0.0.1:1080`. Если на `127.0.0.1:8080` уже
работает контролируемый HTTP-сервер, запрос проходит через весь путь:

```sh
curl --socks5-hostname 127.0.0.1:1080 http://127.0.0.1:8080/
```

Пример сервера разрешает только loopback. Для внешних назначений задайте
необходимые CIDR в `allow`. `0.0.0.0/0` и `::/0` разрешают весь соответствующий
диапазон, включая локальные сети. Собственные ingress endpoints исключаются
из direct route. Клиент не может расширить серверный allowlist.

## Встраивание

Сервер: `Listen(socket, ServerConfig{TLS, Authenticate, Configure, Application,
OnSession})`, затем `Serve(ctx)`. `TokenAuthenticator` создаёт проверку по
снимку principal/token map. `Configure` проверяет namespace/version/payload и
возвращает session-local `Route` с `DialContext`, `ListenPacket`, `Close`.
`Application` обслуживает произвольные типизированные сообщения клиента;
`OnSession` позволяет отправлять сообщения через `Session.Message` в ответном
направлении. На клиенте используется `ClientConfig.Application`.

Клиент: `Dial(ctx, address, ClientConfig{TLS, Token, Configuration})` возвращает
уже аутентифицированный и сконфигурированный `Session`. Затем доступны
`DialContext`, `ListenPacket`, `Message`, `Statistics`, `Shutdown`, `Close`,
`Wait`. `UDPAddress` сохраняет доменный endpoint без клиентского DNS lookup.

Callbacks должны соблюдать context и не вызывать `Session.Message` синхронно
из обработчика входящего control request: запросы одного сеанса обслуживаются
последовательно. Долгие задачи хост организует вне callback.

`Shutdown(ctx)` запрещает новые потоки и согласует drain с peer; по истечении
deadline незавершённые операции прерываются с ошибкой. `Close` прерывает сразу,
`Wait` ждёт освобождения ресурсов. Хост обязан закрывать свои потоки/UDP
ассоциации, чтобы drain мог завершиться. Владение переданными transport sockets
передаётся серверу/сеансу.

Будущий адаптер miray реализует `Route` через выбранные `C.ProxyAdapter`,
сохраняя права, metadata и packet buffer ownership в адаптере. Пакеты quri
не импортируют ядро, не вызывают глобальный `ApplyConfig` и не содержат
Hysteria2/VLESS. Реальная интеграция ядра — следующий этап. Проверенный контракт
с реальными HY2, VLESS/XUDP и следующим quri — в
[mirayintegration](mirayintegration/README.md). Результаты готовности —
[READINESS.md](READINESS.md), применимый RFC-профиль — [RFC-AUDIT.md](RFC-AUDIT.md).

## Границы гарантий

QUIC не сохраняет исходный TCP-сеанс, IP/TCP options и исходный congestion
control. UDP может теряться при перегрузке/потере фрагмента; повторов нет.
`WriteTo` подтверждает постановку в транспорт, не доставку. Срок годности
проверяется до упаковки QUIC; пакеты, уже попавшие в отправку сокета, не отзываются.
Отдельный stream управления не даёт независимого congestion window или
гарантированной задержки на произвольном канале.

RSS не ограничивается лимитом прикладных буферов: QUIC, сокеты, TLS и Go runtime
имеют собственные расходы. Полное соответствие всех зависимостей актуальным
RFC не заявляется; применимые проверки и ограничения описаны в RFC-AUDIT.md.
