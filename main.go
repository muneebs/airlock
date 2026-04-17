package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/muneebs/airlock/cmd/airlock/cli"
	"github.com/muneebs/airlock/cmd/airlock/cli/tui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, tui.Error.Render("Error:"), tui.CleanError(err))
		os.Exit(1)
	}
}
