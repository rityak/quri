module github.com/rityak/quri

go 1.22

require (
	github.com/liyue201/goqr v0.0.0-20200803022322-df443203d4ea
	github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4
	github.com/metacubex/tls v0.1.9
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	go.uber.org/goleak v1.3.0
	golang.org/x/net v0.35.0
	golang.org/x/sync v0.11.0
)

require (
	github.com/metacubex/qpack v0.6.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)

require (
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/http v0.1.8
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	golang.org/x/crypto v0.33.0
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
)

replace github.com/metacubex/quic-go => github.com/rityak/quic-go v0.61.1-0.20261117054205-718b0410a157

replace github.com/metacubex/http => github.com/rityak/http v0.1.9-0.20261115170447-fb1f316d86fc
