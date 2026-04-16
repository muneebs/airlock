//go:build linux

package sysutil

import (
	"os"
	"strconv"
	"strings"
)

func detectMemory() (int64, string) {
	f, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, "unknown"
	}

	for _, line := range strings.Split(string(f), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return kb * 1024, "linux:/proc/meminfo"
				}
			}
			break
		}
	}

	return 0, "unknown"
}
