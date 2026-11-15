# miray integration contract

Отдельный test-only module. Production graph quri не импортирует miray.
Исходники ядра для проверки: `../../miray`, commit
`ca3dd1ac673afa188bfb01fb48922262d9284136`. Published pins наших QUIC,
sing-quic и sing закреплены в этом `go.mod`: Go не наследует `replace`
из импортируемой библиотеки.

Для этого дополнительного набора тестов нужен sibling checkout ядра;
standalone build/tests quri его не требуют. Из корня quri:

```sh
git clone https://github.com/rityak/miray.git ../miray
git -C ../miray checkout ca3dd1ac673afa188bfb01fb48922262d9284136
cd mirayintegration
```

```sh
GOWORK=off go test -race . -count=1 -v
GOWORK=off go vet -unsafeptr=false ./...
```

`unsafeptr` отключён только для этого integration vet: старый `sing/common.Dup`
намеренно переводит указатель через uintptr и помечен `//go:norace`.
Остальные анализаторы и race detector включены. Standalone quri проходит
обычный `go vet ./...` без исключений.

## Проверенный путь

`client configuration → quri server Configure → session-local Route → actual
C.ProxyAdapter → actual miray protocol listener → TCP/UDP destination`.

`integration_test.go` запускает три цепочки: HY2/TLS, VLESS/TLS с XUDP,
следующий quri. TLS первых двух проверяется по fingerprint временного
сертификата; quri использует временную доверенную CA. Проверяются ответ
77824 bytes после TCP EOF, два UDP назначения в одной ассоциации, payload
и source address, service message после трафика и graceful cleanup.

У текущего sing-quic HY2 `MaxUDPSize=4096`; VLESS/XUDP этого ядра не доставляет
пустой UDP payload. Отрицательные случаи проверяются как ожидаемая потеря,
обычный обмен после них продолжается. Ограничения следующих outbound не
расширяют и не уменьшают wire limits самого quri: 65507 bytes для IPv4,
65527 для IPv6, включая пустые датаграммы.

## Что перенести в адаптер ядра

- `route_test.go`: преобразование destination в `C.Metadata`, fresh adapter
  на сессию, explicit CloseWrite через существующий `N.FindUpstream` и
  возврат destination-independent packet transport. Для HY2/XUDP используется
  unspecified metadata `0.0.0.0:0` при открытии; фактический адрес приходит
  с каждым `WriteTo`. Для VLESS без XUDP это преобразование не подходит.
- `Configure`: аутентифицированный principal, проверка namespace/version и
  allowlist профилей. Клиент выбирает только разрешённую session-local
  конфигурацию; глобальный `ApplyConfig` не вызывается. Полный пользовательский
  proxy config требует отдельного валидатора типов, endpoints, credentials,
  CIDR/SSRF policy и запрета рекурсивных маршрутов.
- Владение: Session закрывает Route после остановки handlers; каждый flow
  владеет своим Conn/PacketConn. Метаданные, дополнения inbound и права
  пользователя создаются хостом; исходный IP клиента не выдаётся за адрес
  конечного TCP-соединения. Callbacks соблюдают context.
- В основном `miray/go.mod` при внедрении обновляются все три fork pins из
  этого модуля. Новый sing исправляет race активности UDP; новый sing-quic
  поддерживает write deadlines/отмену очереди; новый QUIC исправляет GREASE.

Регистрация inbound/outbound в YAML, статистика ядра, reload и production
deployment выполняются при внедрении. Этот модуль не меняет рабочий конфиг
ядра и не заменяет проверку после добавления этих точек подключения.
