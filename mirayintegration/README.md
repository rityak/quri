# miray relay host

Необязательный production-модуль для `quri-relay` и его integration tests.
Основные production-пакеты SDK не импортируют miray. На пользователя создаётся
один session-local outbound-адаптер, без процесса ядра и глобального ApplyConfig.

Нужен sibling checkout ядра. Зафиксированный CI commit:
`e9d2a1f6c3e7b7cb5bdde12b18b39044270e794a`.
Из корня quri:

```sh
git clone https://github.com/rityak/miray.git ../miray
git -C ../miray checkout e9d2a1f6c3e7b7cb5bdde12b18b39044270e794a
cd mirayintegration
go build -trimpath -o quri-relay ./cmd/quri-relay
go test -race ./... -count=1 -timeout=3m
go vet -unsafeptr=false ./...
```

Published fork replaces закреплены в этом `go.mod`: Go не наследует замены
зависимого модуля. Исключение `unsafeptr` относится к старому намеренному
`sing/common.Dup`; standalone SDK проходит обычный `go vet ./...`.

## Запуск

`quri-relay -config server.json` использует тот же формат, что standalone CLI.
Обязательны внешний `website`, credentials и сертификат/ACME. `upstream`
принимает VLESS TCP/TLS/REALITY, HY2 или следующий `quri://`. Без него используется
direct с явным CIDR allowlist. `allow_client_upstream` по умолчанию выключен;
при включении авторизованный клиент передаёт один фиксированный URL в control.
Прикладные правила маршрутизации остаются на клиенте.

`NewAdapter` принимает готовый `constant.ProxyAdapter` для встраивающего хоста.
`NewOutbound` проверяет URL поддерживаемого второго плеча. Произвольные глобальные
конфиги ядра, неподдерживаемые WS-параметры и insecure TLS не принимаются.
Метаданные назначения и destination-independent UDP передаются адаптеру;
TCP CloseWrite проходит через существующий `FindUpstream` ядра.

## Проверенный тракт

Матрица: клиентский outbound ядра через `adapter.ParseProxy` → h3/h2 relay →
VLESS/TLS, VLESS/REALITY или HY2 → настоящие TCP/UDP назначения. Проверяются
ответ после TCP EOF, два UDP назначения, payload до лимита Quri 1150 байт и
закрытие ресурсов. REALITY fixture использует локальный TLS origin и тестовые
X25519 keys. Второе плечо проверяется против listener того же ядра; независимый
HTTP/3 peer для первого плеча находится в соседнем модуле `interop`.

Linux packaging и пробная установка выполняются CI через `deploy/build.py`.
Реальный systemd service, live ACME и полевые мобильные сети не проверялись.
