package sysutil

import (
	"testing"
)

func TestParseMemoryString(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		// IEC (binary) units: 1024-based
		{"4GiB", 4 * 1024 * 1024 * 1024, false},
		{"2048MiB", 2048 * 1024 * 1024, false},
		{"8GiB", 8 * 1024 * 1024 * 1024, false},
		{"1KiB", 1024, false},
		// SI (decimal) units: 1000-based
		{"1GB", 1000 * 1000 * 1000, false},
		{"1MB", 1000 * 1000, false},
		{"1KB", 1000, false},
		// Bare numbers
		{"4096", 4096, false},
		// Bare letters: IEC (binary) for backward compatibility
		{"2G", 2 * 1024 * 1024 * 1024, false},
		{"512M", 512 * 1024 * 1024, false},
		// Empty string = no requirement
		{"", 0, false},
		// Invalid inputs
		{"invalid", 0, true},
		{"4xyz", 0, true},
		{"GiB", 0, true},
		{"-1GiB", -1 * 1024 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseMemoryString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseMemoryString(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseMemoryString(%q) unexpected error: %v", tt.input, err)
				return
			}
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

	issues, err := CheckResources(req, available)
	if err != nil {
		t.Fatalf("CheckResources() error: %v", err)
	}
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

	issues, err := CheckResources(req, available)
	if err != nil {
		t.Fatalf("CheckResources() error: %v", err)
	}
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

	issues, err := CheckResources(req, available)
	if err != nil {
		t.Fatalf("CheckResources() error: %v", err)
	}
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

	issues, err := CheckResources(req, available)
	if err != nil {
		t.Fatalf("CheckResources() error: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("empty strings should skip checks, got %v", issues)
	}
}

func TestCheckResourcesMalformedInput(t *testing.T) {
	available := Resources{
		CPUCores:    8,
		MemoryBytes: 16 * 1024 * 1024 * 1024,
		DiskBytes:   100 * 1024 * 1024 * 1024,
	}

	tests := []struct {
		name    string
		req     Requirements
		wantErr bool
	}{
		{"malformed memory", Requirements{CPU: 2, Memory: "4xyz", Disk: "20GiB"}, true},
		{"malformed disk", Requirements{CPU: 2, Memory: "4GiB", Disk: "bananas"}, true},
		{"valid both", Requirements{CPU: 2, Memory: "4GiB", Disk: "20GiB"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CheckResources(tt.req, available)
			if tt.wantErr && err == nil {
				t.Error("expected error for malformed input")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetectResources(t *testing.T) {
	res := DetectResources()
	if res.CPUCores <= 0 {
		t.Error("expected positive CPU cores")
	}
	if res.MemorySource == "unknown" {
		t.Error("expected memory source to be detected on this platform")
	}
	if res.MemorySource != "unknown" && res.MemoryBytes <= 0 {
		t.Error("expected positive memory bytes when source is known")
	}
	if res.DiskBytes <= 0 {
		t.Error("expected positive disk bytes")
	}
	if res.TotalMemory == "" {
		t.Error("expected non-empty total memory string")
	}
}

func TestDetectResourcesMemorySource(t *testing.T) {
	res := DetectResources()
	if res.MemorySource == "" {
		t.Error("expected non-empty memory source")
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
