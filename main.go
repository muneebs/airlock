package main

import (
	"os"

	"github.com/muneebs/airlock/cmd/airlock/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
