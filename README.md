# quri

Самостоятельный SDK первого плеча: HTTP/3 (`h3`) с резервным HTTP/2 (`h2`).
TLS 1.3, HTTP CONNECT для TCP, CONNECT-UDP для UDP, один фиксированный outbound
на соединение. Маршрутизация между профилями выполняется на клиенте.

## Сборка

```sh
go build -trimpath -o quri ./cmd/quri
go test ./...
go vet ./...
```

Go 1.22+, проверочный CI — Go 1.26. Пакеты: `client`, `session`, `route`,
`transport`, `certificates`, `config`. Production SDK не импортирует miray.
Встраивающее приложение должно повторить published `replace` из go.mod:
Go не наследует замены зависимого модуля.

## Запуск

```sh
quri -config server.json
quri -config client.json
quri -link 'quri://TOKEN@relay.example:443?sni=relay.example&transports=h3,h2'
```

Сервер слушает TCP и UDP на одном адресе. `website` — обязательный URL
внешнего сайта, например `http://127.0.0.1:8080`; встроенных страниц нет.
TLS завершается в quri для проверки TLS-exporter HMAC. Обычные запросы
передаются внешнему сайту с его статусами и содержимым. Валидный auth proof
не передаётся backend. Сертификат принадлежит собственному домену relay.

`certificate` и `key` читаются при старте и обновляются каждые 30 секунд.
Неполная или ошибочная замена сохраняет предыдущую исправную пару.
Альтернатива — `domain`, `acme_cache`, `acme_email`: ACME TLS-ALPN-01 требует
доступного снаружи TCP/443. Реальный выпуск через CA ещё не проверен.

Примеры — `examples/server.json`, `examples/client.json`. Токен должен
содержать не менее 32 байт случайного материала; ссылки и конфиги секретны.
Сервер direct требует явный список разрешённых CIDR. Standalone `upstream`
принимает следующий `quri://` узел. Модуль `mirayintegration` предоставляет
session-local адаптеры VLESS/HY2; глобальные правила ядра не загружаются.

## Ограничения

Один UDP-пакет передаётся одной DATAGRAM без фрагментации. По умолчанию
payload ограничен 1150 байт; большие пакеты отбрасываются. В h2 UDP передаётся
надёжными упорядоченными capsules и разделяет TCP head-of-line blocking.
Реконнект восстанавливает UDP-ассоциации; существующие TCP-потоки закрываются.

Ветвь меняет прежний Go API и несовместима с удалённым wire `quri/1`.
`0 allocs/op` подтверждено для DATAGRAM codec, не для всего UDP-тракта.
Migration/port rotation, Chrome fingerprint, padding и BBR ещё не приняты.
Сайт и ALPN h3 сами по себе не доказывают устойчивость к DPI/зондированию.

Изменения и текущие границы проверки — [CHANGELOG.md](CHANGELOG.md).
Wire mapping — [PROTOCOL.md](PROTOCOL.md). Независимый HTTP/3 peer — `interop/`.
