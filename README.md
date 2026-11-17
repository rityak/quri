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
quri -config client.json -export-link
quri -config client.json -qr private-profile.png
```

Сервер слушает TCP и UDP на одном адресе. `website` — обязательный URL
внешнего сайта, например `http://127.0.0.1:8080`; встроенных страниц нет.
TLS завершается в quri для проверки TLS-exporter HMAC. Обычные запросы
передаются внешнему сайту с его статусами и содержимым. Валидный auth proof
не передаётся backend. Сертификат принадлежит собственному домену relay.

`certificate` и `key` читаются при старте и обновляются каждые 30 секунд.
Неполная или ошибочная замена сохраняет предыдущую исправную пару.
Альтернатива — `domain`, `acme_cache`, `acme_email`: ACME TLS-ALPN-01 требует
доступного снаружи TCP/443. Встроенный ACME issuer с реальным CA ещё не проверен;
внешний certbot, выдача сертификата и renewal dry-run проверены.

Примеры — `examples/server.json`, `examples/client.json`. Токен должен
содержать не менее 32 байт случайного материала; ссылки и конфиги секретны.
Сервер direct требует явный список разрешённых CIDR. Standalone `upstream`
принимает следующий `quri://` узел. Модуль `mirayintegration` предоставляет
session-local адаптеры VLESS/HY2; глобальные правила ядра не загружаются.

`quri-relay` с адаптерами miray собирается из `mirayintegration/`:

```sh
cd mirayintegration && go build -trimpath -o quri-relay ./cmd/quri-relay
```

Linux-архив с обоими бинарниками и установщиком:

```sh
python3 deploy/build.py --arch amd64
tar -xzf dist/quri-relay-linux-amd64.tar.gz -C /path/to/package
sudo /path/to/package/install.sh --config /absolute/path/server.json
```

Пример серверного конфига — `deploy/server.example.json`. Сначала задайте
собственный домен, секреты, URL внешнего сайта и outbound/allowlist.
Установщик проверяет конфиг, создаёт отдельного системного пользователя и unit;
существующий отличающийся конфиг не перезаписывается. Для предварительной
проверки доступны `-check`, `-check-service` и `--no-start --prefix /staging`.

## Ограничения

Один UDP-пакет передаётся одной DATAGRAM без фрагментации. По умолчанию
payload ограничен 65507 байт. В h3 дополнительно действует текущий PMTU
соединения: пакет, который не помещается в QUIC DATAGRAM вместе с заголовками,
отбрасывается. Размер не фиксируется ниже 1200 байт, необходимых QUIC Initial;
после DPLPMTUD могут передаваться и более крупные пакеты. В h2 UDP передаётся
надёжными упорядоченными capsules и разделяет TCP head-of-line blocking.
Реконнект восстанавливает UDP-ассоциации; существующие TCP-потоки закрываются.

Закрытие TCP-туннеля сначала отправляет FIN, сохраняя уже принятые байты.
В h2 полный `Close` ждёт отправки последних DATA/END_STREAM не дольше
`open_timeout_ns`, затем освобождает ответ. Явный deadline по-прежнему
прерывает запрос сразу. FIN со стороны сервера не прекращает встречный upload.

H3 поддерживает миграцию локального UDP-сокета с сохранением сессии и потоков.
`client.Manager.Migrate(ctx)` можно вызвать по событию смены сети. После
неуспешной проверки пути соединение также пробует миграцию автоматически;
если новый путь не работает, менеджер переподключается. Смена удалённого порта
живого соединения не реализована: `ports` участвует в установлении соединения.
Keepalive и проверка здоровья идут со случайным интервалом 10–25 секунд.
В JSON `limits` интервалы задаются в наносекундах: `keepalive_min_ns`,
`keepalive_max_ns`, `connection_idle_timeout_ns` (по умолчанию 60 секунд).
`idle_timeout_ns` отдельно ограничивает простой UDP-туннеля. При настройке
keepalive максимальный интервал вместе с бюджетом `open_timeout_ns` должен
быть меньше connection idle timeout на обеих сторонах.

Ветвь меняет прежний Go API и несовместима с удалённым wire `quri/1`.
`0 allocs/op` подтверждено для DATAGRAM codec, capsule decoder и direct UDP,
не для всего UDP-тракта. Ротация удалённых портов, Chrome fingerprint,
стартовый padding и эксперимент с BBR ещё не реализованы.
Сайт и ALPN h3 сами по себе не доказывают устойчивость к DPI/зондированию.

Изменения и текущие границы проверки — [CHANGELOG.md](CHANGELOG.md).
Wire mapping — [PROTOCOL.md](PROTOCOL.md). Независимый HTTP/3 peer — `interop/`.
