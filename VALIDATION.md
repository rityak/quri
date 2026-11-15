# quri · проверка T-178 / T-179

T-181: идентификаторы и пути в исторических текстовых отчётах нормализованы
под quri. Старые CPU/memory profiles, generated archives и binaries удалены
при очистке, команды ниже позволяют получить новые profiles. Числа T-178
сохранены как исторические; переименование не является повторным замером.

Дата: 2026-11-15. Go 1.26.7, Windows amd64 и Linux amd64. QUIC:
T-178: `rityak/quic-go` `d62788b698d7ed065485fc79a452007ce1742f92`;
upstream peer для независимого теста — quic-go v0.64.1.

T-179: актуальный pin QUIC — `a6ba8bb51c8949b66eebf4058fb92bdded09f256`.
Актуальная приёмка, зависимые исправления sing/sing-quic и границы готовности
описаны в [READINESS.md](READINESS.md). Измерения ниже относятся к T-178,
после hardening T-179 performance benchmarks повторно не заявляются.

## Выполнено

| Проверка | Результат |
|---|---|
| `go test ./...`, `go vet ./...` в самостоятельном модуле | PASS Windows и Linux |
| `go test -p 2 -race ./...` | PASS Linux, включая реальные CLI-процессы |
| Чистая сборка с опубликованным pin, без go.work/локального replace | PASS; `go list -m -json` указывает на опубликованный rityak module |
| Windows/Linux amd64 binaries | Собраны `go build -trimpath`; в runtime не нужен miray |
| TCP half-close | Запрос до EOF, ответ 294912 bytes после EOF, без усечения |
| TCP при потерях/перестановке/дублях и UDP MTU 1200 | PASS детерминированный PacketConn profile с сохранением payload |
| IPv6 transport, IPv6 destination, domain TCP destination | PASS, включая localhost и стандартный Happy Eyeballs |
| UDP full path | Payload 0/1/1024/8192/65507 bytes через сервер к настоящему UDP socket и обратно |
| Reassembly | Независимый hex vector, out-of-order, дубли, overlap, потеря/expiry, memory caps, fuzz |
| Deadlines/cancel | Read deadline update, queued write deadline update, canceled Open, cleanup byte accounting |
| Lifecycle после временного timeout | TCP read timeout не завершает поток; после смены deadline ответ дочитывается. Односторонний UDP сохраняет ассоциацию без ответов через несколько idle periods |
| Access control | Неверный token при доверенном TLS, запрещённая initial configuration, повторная configuration, CIDR denial, stale/conflicting request IDs |
| Ошибки назначения | `connection refused` отличим от policy denial на Windows/Linux; Windows WSA code учтён явно |
| Service messages | Client→server и server→client; replay последних ответов, stale ID не применяется повторно, более 16 сообщений за сеанс |
| SOCKS5 client path | x/net/proxy CONNECT и независимый raw UDP ASSOCIATE; association завершается с TCP control, закрытие listener сохраняет живую ассоциацию |
| CLI config pipeline | Два собранных процесса, relative CA/cert/key paths, реальный HTTP target через SOCKS5→quri→server; не только library echo |
| Independent peer | Отдельный test-модуль кодирует wire format и использует upstream QUIC; TLS/Hello/config/TCP half-close/UDP PASS |
| Наш QUIC fork | Queue admission cancellation/expiry, legacy queue tests, packer anti-starvation, framer round-robin и HTTP3 DATAGRAM под race PASS |
| miray regression с новым QUIC pin | HY2 TLS, HY2 upload-before-response close, TUIC TLS, TUIC large UDP PASS (Windows, отдельный modfile, основной go.mod не менялся) |

Fuzzing на Linux: по 3 s, два worker на `FuzzFraming`, `FuzzDatagram`,
`FuzzSOCKSAddress`; в сохранённом прогоне 68376/71815/68460 executions
(208651 суммарно), crashes не найдено. Короткий fuzz-прогон не заменяет
длительное fuzzing перед release.

Linux-проверки выполнялись во Франкфурте в отдельном transient unit:
`MemoryMax=2G`, `MemorySwapMax=0`, `OOMPolicy=continue`, `GOMAXPROCS=2`.
Службы пользователя и их конфигурации не менялись.

Kernel network profile: отдельный namespace `quri-t178`, loopback MTU 1280,
netem delay `3ms 1ms`, loss `0.5%`, duplicate `0.1%`, reorder `1%`.
TCP half-close и recovery tests PASS. Namespace удалён trap после проверки;
маршруты, firewall и SSH основного namespace не изменялись.

## Исходные измерения

При 8 непрерывных TCP writers и UDP producer по 1000-byte payload,
10 control requests на Linux loopback: p50 **2.143 ms**, max/p95 **4.405 ms**.
При десяти наблюдениях p95 здесь совпадает с максимумом; это smoke baseline,
не статистически установленная задержка на реальном канале.

Serial UDP echo baseline, клиент и сервер в одном test-процессе, 100 iterations:

| Payload | ns/op | B/op | allocs/op |
|---:|---:|---:|---:|
| 64 | 76462 | 6660 | 104 |
| 1200 | 109617 | 18353 | 140 |
| 8192 | 200920 | 87306 | 325 |
| 65507 | 976985 | 666934 | 1985 |

Это round-trip в последовательном цикле с direct UDP target, не максимальная
скорость туннеля. В B/op включены обе стороны и target. Преимущества над
другими протоколами из этих чисел не следуют. Копии/аллокации требуют отдельного
профилирования до оптимизаций.

Отдельный CPU/memory profile для payload 1200, `-benchtime=3s`, 32349 iterations:
112238 ns/op, 18019 B/op, 138 allocs/op. Весь profiled test-процесс (включая
setup, warmup и обе стороны) занял 4.783 s wall, 2.813 s user CPU, 2.087 s
system CPU; peak RSS **20604 KiB** по Linux getrusage, не расчёт из Go heap.
Это один co-located session, не оценка памяти для 64 клиентов. CPU profile:
41.56% samples в Syscall6, reassembler 2.06% flat / 3.91% cumulative;
оптимизация по этому начальному профилю в T-178 не выполнялась.

Команды восстановления профиля:

```sh
go test -c -o quri.test .
./quri.test -test.run '^$' -test.bench '^BenchmarkUDP/1200$' -test.benchtime=3s -test.benchmem -test.cpuprofile=cpu.pprof -test.memprofile=mem.pprof
go tool pprof -top quri.test cpu.pprof
```

Сырые логи/профили/бинарники в родительском workspace:
`tools/artifacts/quri/` (не в Git). Исходники и спецификация — в модуле.

## Закрытые в T-179 ограничения T-178

- В T-178 полный root-suite QUIC-форка на Windows был не зелёный:
  `TestDial` (четыре варианта) ждёт UDP и получает timeout;
  `TestTransportAndDialConcurrentClose` получает TLS ServerName validation
  вместо ожидаемого transport-closed error. Оба сбоя воспроизведены до патча
  на опубликованном `dddc617d9406`; в T-179 fixtures получили проверяемый ServerName.
- T-178 / часть T-163: форк объявлял GREASE, но parser long header отклонял cleared
  fixed bit. Это известное расхождение с RFC 9287 §3. Для очереди DATAGRAM
  оно не менялось. В T-179 parser исправлен с сохранением AAD и тестами long-header
  типов; full QUIC suites проходят Windows/Linux, включая Linux race.
  Применимый профиль и оставшиеся границы аудита — RFC-AUDIT.md.
- T-179 закрыл scoped RFC audit, restart, 64 sessions и 64 TCP/32 UDP flows.
  Полного аудита всех возможностей TLS-форка, многочасового soak, всех
  combinations NAT/migration и проверки DPI/реального канала нет.
- Toolchain Go 1.20 отдельно не запускался. Production module имеет `go 1.20`,
  interop test-модуль требует Go 1.26 из-за upstream test dependency.
- T-179 добавил harness реальных miray/HY2/VLESS/следующего quri с session-local
  route. Регистрация в основном ядре и полный session-local rule graph остаются
  отдельным этапом D-018.

Соответствие собственному framing проверено vectors/fuzz/independent peer;
это не объявление всего стека RFC-compliant и не выпуск production release.
