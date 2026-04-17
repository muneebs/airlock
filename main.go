package main

import (
	"fmt"
	"os"

	"github.com/muneebs/airlock/cmd/airlock/cli"
	"github.com/muneebs/airlock/cmd/airlock/cli/tui"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, tui.Error.Render("Error:"), tui.CleanError(err))
		os.Exit(1)
	}
}
