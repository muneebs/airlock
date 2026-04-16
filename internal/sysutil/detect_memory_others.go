//go:build !darwin && !linux

package sysutil

func detectMemory() (int64, string) {
	return 0, "unknown"
}
