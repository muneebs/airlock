package lima

import (
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "test-vm", false},
		{"valid with dots", "vm.v2.0", false},
		{"valid with underscore", "test_vm", false},
		{"valid alphanumeric", "vm123", false},
		{"empty string", "", true},
		{"path traversal dot dot", "../../etc", true},
		{"startsWith dot", ".hidden", true},
		{"startsWith hyphen", "-flag", true},
		{"contains ..", "vm..bad", true},
		{"slash", "vm/sub", true},
		{"null byte like", "vm\x00bad", true},
		{"semicolon", "vm;bad", true},
		{"space", "vm bad", true},
		{"single dot only", ".", true},
		{"double dot only", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "airlock", false},
		{"valid with underscore", "airlock_user", false},
		{"valid with digit", "user123", false},
		{"valid starts with underscore", "_systemd", false},
		{"empty string", "", true},
		{"starts with hyphen", "-bad", true},
		{"starts with dot", ".hidden", true},
		{"contains space", "air lock", true},
		{"contains semicolon", "airlock;rm", true},
		{"sudo injection", "root -u root", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUsername(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
