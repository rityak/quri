module github.com/rityak/quri/interop

go 1.26.0

require (
	github.com/quic-go/quic-go v0.64.1
	github.com/rityak/quri v0.0.0
)

require (
	github.com/metacubex/cpu v0.1.0 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/http v0.1.8 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	github.com/metacubex/tls v0.1.9 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace github.com/rityak/quri => ..

replace github.com/metacubex/quic-go => github.com/rityak/quic-go v0.61.1-0.20261115171335-8f0b372b74bf

replace github.com/metacubex/http => github.com/rityak/http v0.1.9-0.20261115170447-fb1f316d86fc
