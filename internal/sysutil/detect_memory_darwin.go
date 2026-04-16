//go:build darwin

package sysutil

import (
	"os/exec"
	"strconv"
	"strings"
)

func detectMemory() (int64, string) {
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return 0, "unknown"
	}

	memBytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, "unknown"
	}

	return memBytes, "darwin:sysctl"
}
