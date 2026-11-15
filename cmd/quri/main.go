package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/rityak/quri/command"
)

type configFile = command.Config

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := command.Run(ctx, os.Args[1:], nil); err != nil && !errors.Is(err, flag.ErrHelp) {
		slog.Error("quri stopped", "error", err)
		os.Exit(1)
	}
}
