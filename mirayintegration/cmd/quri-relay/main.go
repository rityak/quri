package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/rityak/quri/command"
	"github.com/rityak/quri/mirayintegration"
	"github.com/rityak/quri/route"
)

func main() {
	// The standalone host does not load the core configuration's IP policy.
	resolver.DisableIPv6 = false
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := command.Run(ctx, os.Args[1:], func(ctx context.Context, link string) (route.Route, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return mirayintegration.NewOutbound(link)
	})
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error("quri relay stopped", "error", err)
		os.Exit(1)
	}
}
