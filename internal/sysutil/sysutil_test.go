package sysutil

import (
	"testing"
)

func TestParseMemoryString(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"4GiB", 4 * 1024 * 1024 * 1024},
		{"2048MiB", 2048 * 1024 * 1024},
		{"8GiB", 8 * 1024 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"4096", 4096},
		{"2G", 2 * 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"", 0},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMemoryString(tt.input)
			if got != tt.expected {
				t.Errorf("parseMemoryString(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCheckResourcesSufficient(t *testing.T) {
	available := Resources{
		CPUCores:    8,
		MemoryBytes: 16 * 1024 * 1024 * 1024,
		DiskBytes:   100 * 1024 * 1024 * 1024,
	}

	req := Requirements{
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
	}

	issues := CheckResources(req, available)
	if len(issues) != 0 {
		t.Errorf("expected no insufficiencies, got %v", issues)
	}
}

func TestCheckResourcesInsufficientCPU(t *testing.T) {
	available := Resources{
		CPUCores:    1,
		MemoryBytes: 16 * 1024 * 1024 * 1024,
		DiskBytes:   100 * 1024 * 1024 * 1024,
	}

	req := Requirements{
		CPU:    4,
		Memory: "4GiB",
		Disk:   "20GiB",
	}

	issues := CheckResources(req, available)
	if len(issues) == 0 {
		t.Error("expected CPU insufficiency")
	}
	found := false
	for _, i := range issues {
		if i.Resource == "cpu" {
			found = true
		}
	}
	if !found {
		t.Error("expected CPU insufficiency in issues")
	}
}

func TestCheckResourcesInsufficientMemory(t *testing.T) {
	available := Resources{
		CPUCores:    8,
		MemoryBytes: 2 * 1024 * 1024 * 1024,
		DiskBytes:   100 * 1024 * 1024 * 1024,
	}

	req := Requirements{
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
	}

	issues := CheckResources(req, available)
	if len(issues) == 0 {
		t.Error("expected memory insufficiency")
	}
}

func TestCheckResourcesEmptyStringsOK(t *testing.T) {
	available := Resources{
		CPUCores:    2,
		MemoryBytes: 4 * 1024 * 1024 * 1024,
		DiskBytes:   20 * 1024 * 1024 * 1024,
	}

	req := Requirements{
		CPU:    2,
		Memory: "",
		Disk:   "",
	}

	issues := CheckResources(req, available)
	if len(issues) != 0 {
		t.Errorf("empty strings should skip checks, got %v", issues)
	}
}

func TestDetectResources(t *testing.T) {
	res := DetectResources()
	if res.CPUCores <= 0 {
		t.Error("expected positive CPU cores")
	}
	if res.MemoryBytes <= 0 {
		t.Error("expected positive memory bytes")
	}
	if res.DiskBytes <= 0 {
		t.Error("expected positive disk bytes")
	}
	if res.TotalMemory == "" {
		t.Error("expected non-empty total memory string")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{4 * 1024 * 1024 * 1024, "4GiB"},
		{2048 * 1024 * 1024, "2GiB"},
		{512 * 1024 * 1024, "512MiB"},
		{1024, "1KiB"},
		{500, "500B"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.expected)
		}
	}
}
