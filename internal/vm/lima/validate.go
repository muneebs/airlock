package lima

import (
	"fmt"
	"regexp"
	"strings"
)

var safeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if !safeNameRe.MatchString(name) {
		return fmt.Errorf("name %q contains invalid characters; only alphanumeric, underscore, dot, and hyphen are allowed, and must not start with a special character", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("name %q must not contain ..", name)
	}
	return nil
}

func validateUsername(user string) error {
	if user == "" {
		return fmt.Errorf("user is required")
	}
	matched, err := regexp.MatchString(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`, user)
	if err != nil {
		return fmt.Errorf("validate user: %w", err)
	}
	if !matched {
		return fmt.Errorf("user %q contains invalid characters; only alphanumeric, underscore, dot, and hyphen are allowed", user)
	}
	return nil
}
