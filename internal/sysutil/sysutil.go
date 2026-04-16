// Package sysutil detects system resource limits to ensure sandbox creation
// won't exceed available capacity. It queries CPU cores, memory, and disk space
// and provides a simple "can I create a sandbox with these requirements?" check.
package sysutil

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Resources describes the host system's available resources.
type Resources struct {
	CPUCores     int    `json:"cpu_cores"`
	TotalMemory  string `json:"total_memory"`
	MemoryBytes  int64  `json:"memory_bytes"`
	MemorySource string `json:"memory_source"`
	DiskFree     string `json:"disk_free"`
	DiskBytes    int64  `json:"disk_bytes"`
}

// Requirements describes what a sandbox needs.
type Requirements struct {
	CPU    int    `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
}

// Insufficiency represents a resource that doesn't meet requirements.
type Insufficiency struct {
	Resource  string `json:"resource"`
	Required  string `json:"required"`
	Available string `json:"available"`
}

func (i Insufficiency) Error() string {
	return fmt.Sprintf("insufficient %s: need %s, have %s", i.Resource, i.Required, i.Available)
}

// CheckResources verifies that the host can satisfy the given requirements.
// Returns a list of insufficiencies (empty if everything is fine).
// Returns an error if any requirement string is malformed.
func CheckResources(req Requirements, available Resources) ([]Insufficiency, error) {
	var issues []Insufficiency

	if req.CPU > available.CPUCores {
		issues = append(issues, Insufficiency{
			Resource:  "cpu",
			Required:  strconv.Itoa(req.CPU),
			Available: strconv.Itoa(available.CPUCores),
		})
	}

	if req.Memory != "" {
		reqMemBytes, err := parseMemoryString(req.Memory)
		if err != nil {
			return nil, fmt.Errorf("invalid memory requirement %q: %w", req.Memory, err)
		}
		if reqMemBytes > 0 && reqMemBytes > available.MemoryBytes {
			issues = append(issues, Insufficiency{
				Resource:  "memory",
				Required:  req.Memory,
				Available: available.TotalMemory,
			})
		}
	}

	if req.Disk != "" {
		reqDiskBytes, err := parseMemoryString(req.Disk)
		if err != nil {
			return nil, fmt.Errorf("invalid disk requirement %q: %w", req.Disk, err)
		}
		if reqDiskBytes > 0 && reqDiskBytes > available.DiskBytes {
			issues = append(issues, Insufficiency{
				Resource:  "disk",
				Required:  req.Disk,
				Available: available.DiskFree,
			})
		}
	}

	return issues, nil
}

// DetectResources queries the current system for available resources.
func DetectResources() Resources {
	res := Resources{
		CPUCores: runtime.NumCPU(),
	}

	memBytes, memSource := detectMemory()
	res.MemoryBytes = memBytes
	res.MemorySource = memSource
	if memSource == "unknown" {
		res.TotalMemory = "unknown"
	} else {
		res.TotalMemory = formatBytes(memBytes)
	}

	diskBytes, diskStr := detectDisk()
	res.DiskBytes = diskBytes
	res.DiskFree = diskStr

	return res
}

// parseMemoryString converts strings like "4GiB", "2048MiB", "4096" to bytes.
// Returns (0, nil) for empty strings. Returns (0, error) for malformed input.
func parseMemoryString(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSpace(s)

	// IEC (binary) units: 1024-based
	multipliers := map[string]int64{
		"GiB": 1024 * 1024 * 1024,
		"MiB": 1024 * 1024,
		"KiB": 1024,
		// SI (decimal) units: 1000-based
		"GB": 1000 * 1000 * 1000,
		"MB": 1000 * 1000,
		"KB": 1000,
		// Bare letters: treat as IEC (binary) for backward compatibility
		"G": 1024 * 1024 * 1024,
		"M": 1024 * 1024,
		"K": 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(s, suffix) {
			numStr := strings.TrimSuffix(s, suffix)
			num, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return 0, fmt.Errorf("parse numeric part of %q: %w", s, err)
			}
			return int64(num * float64(mult)), nil
		}
	}

	num, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %q as integer bytes: %w", s, err)
	}
	return num, nil
}

func detectDisk() (int64, string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(homeDir, &stat); err == nil {
		freeBytes := int64(stat.Bavail) * int64(stat.Bsize)
		return freeBytes, formatBytes(freeBytes)
	}

	return 50 * 1024 * 1024 * 1024, "50GiB"
}

func formatBytes(b int64) string {
	const (
		GiB = 1024 * 1024 * 1024
		MiB = 1024 * 1024
		KiB = 1024
	)
	switch {
	case b >= GiB:
		return fmt.Sprintf("%.0fGiB", float64(b)/float64(GiB))
	case b >= MiB:
		return fmt.Sprintf("%.0fMiB", float64(b)/float64(MiB))
	case b >= KiB:
		return fmt.Sprintf("%.0fKiB", float64(b)/float64(KiB))
	default:
		return fmt.Sprintf("%dB", b)
	}
}
