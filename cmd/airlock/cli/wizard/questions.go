// Package wizard provides an interactive TUI for creating airlock sandboxes.
package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/muneebs/airlock/internal/config"
)

// Styles for the wizard UI.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("69"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)
)

// SourceInfo holds information about the code source.
type SourceInfo struct {
	Path     string
	IsGitHub bool
}

// DeriveSandboxName generates a name from source path or URL.
func DeriveSandboxName(source string) string {
	// Handle GitHub URLs
	if strings.HasPrefix(source, "gh:") {
		parts := strings.SplitN(strings.TrimPrefix(source, "gh:"), "/", 2)
		if len(parts) == 2 {
			return sanitizeName(strings.TrimSuffix(parts[1], ".git"))
		}
		return sanitizeName(strings.TrimPrefix(source, "gh:"))
	}

	if strings.HasPrefix(source, "https://github.com/") {
		parts := strings.SplitN(strings.TrimPrefix(source, "https://github.com/"), "/", 3)
		if len(parts) >= 2 {
			return sanitizeName(strings.TrimSuffix(parts[1], ".git"))
		}
	}

	// Handle local paths
	base := filepath.Base(source)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" || base == "." || base == ".." {
		return "sandbox"
	}
	return sanitizeName(base)
}

func sanitizeName(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i == 0 && !isAlpha(r) && r != '_' {
			b.WriteByte('_')
		}
		if isAlphaNum(r) || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if result == "" {
		return "sandbox"
	}
	return result
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isAlphaNum(r rune) bool {
	return isAlpha(r) || (r >= '0' && r <= '9')
}

// Run starts the interactive wizard and returns the result.
func Run(source string) (*WizardResult, error) {
	var result WizardResult
	result.Source = source

	// Auto-detect name from source
	suggestedName := DeriveSandboxName(source)

	// Step 1: Source confirmation (if not provided)
	if source == "" {
		var sourceInput string
		sourceForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Where is the code you want to run?").
					Description("Enter a local path or GitHub URL (gh:user/repo)").
					Placeholder("./my-project or gh:user/repo").
					Value(&sourceInput).
					Validate(func(s string) error {
						if s == "" {
							return fmt.Errorf("source is required")
						}
						return nil
					}),
			),
		)

		if err := sourceForm.Run(); err != nil {
			return nil, err
		}

		result.Source = sourceInput
		suggestedName = DeriveSandboxName(sourceInput)
	}

	// Step 2: Sandbox name
	result.Name = suggestedName
	nameForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("What should we call this sandbox?").
				Description("This name will identify your sandbox in airlock").
				Value(&result.Name).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("name is required")
					}
					if !isValidSandboxName(s) {
						return fmt.Errorf("name must contain only letters, numbers, hyphens, underscores, and dots")
					}
					return nil
				}),
		),
	)

	if err := nameForm.Run(); err != nil {
		return nil, err
	}

	// Step 3: Trust level
	trustOption := string(TrustCautious) // Default
	trustOptions := []huh.Option[string]{}
	for _, info := range TrustLevels() {
		desc := fmt.Sprintf("%s - %s", info.Label, info.Description)
		trustOptions = append(trustOptions, huh.NewOption(desc, string(info.Level)))
	}

	trustForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("How much do you trust this software?").
				Description("Choose the option that best describes your situation").
				Options(trustOptions...).
				Value(&trustOption),
		),
	)

	if err := trustForm.Run(); err != nil {
		return nil, err
	}

	result.TrustLevel = TrustLevel(trustOption)

	// Show warning for insecure choices
	if IsInsecureChoice(result.TrustLevel) {
		for _, info := range TrustLevels() {
			if info.Level == result.TrustLevel && info.Warning != "" {
				fmt.Println(warningStyle.Render("⚠️  " + info.Warning))
				fmt.Println()
				break
			}
		}
	}

	// Step 4: Resource level
	resourceOption := string(ResourceStandard) // Default
	resourceOptions := []huh.Option[string]{}
	for _, info := range ResourceLevels() {
		desc := fmt.Sprintf("%s - %s (%d CPU, %s RAM)", info.Label, info.Description, info.CPU, info.Memory)
		resourceOptions = append(resourceOptions, huh.NewOption(desc, string(info.Level)))
	}

	resourceForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("How demanding is this software?").
				Description("This determines how much of your computer's resources to allocate").
				Options(resourceOptions...).
				Value(&resourceOption),
		),
	)

	if err := resourceForm.Run(); err != nil {
		return nil, err
	}

	result.ResourceLevel = ResourceLevel(resourceOption)

	// Step 5: Network level
	networkOption := string(NetworkDownloads) // Default
	networkOptions := []huh.Option[string]{}
	for _, info := range NetworkLevels() {
		desc := fmt.Sprintf("%s - %s", info.Label, info.Description)
		networkOptions = append(networkOptions, huh.NewOption(desc, string(info.Level)))
	}

	networkForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What network access does it need?").
				Description("Choose how the sandbox can access the internet").
				Options(networkOptions...).
				Value(&networkOption),
		),
	)

	if err := networkForm.Run(); err != nil {
		return nil, err
	}

	result.NetworkLevel = NetworkLevel(networkOption)

	// Show warning for insecure network choice
	if IsInsecureNetwork(result.NetworkLevel) {
		for _, info := range NetworkLevels() {
			if info.Level == result.NetworkLevel && info.Warning != "" {
				fmt.Println(warningStyle.Render("⚠️  " + info.Warning))
				fmt.Println()
				break
			}
		}
	}

	// Step 6: Persistence options
	startAtLogin := false // Default
	saveConfig := true    // Default

	persistenceForm := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Save configuration file?").
				Description("Creates airlock.toml so you can easily restart this sandbox later").
				Value(&saveConfig),

			huh.NewConfirm().
				Title("Start at login?").
				Description("Automatically start this sandbox when you log in").
				Value(&startAtLogin),
		),
	)

	if err := persistenceForm.Run(); err != nil {
		return nil, err
	}

	result.StartAtLogin = startAtLogin
	result.SaveConfig = saveConfig

	// Step 7: Confirmation
	cpu, memory := MapResourceLevel(result.ResourceLevel)
	profileName := MapTrustLevelToProfile(result.TrustLevel)
	defaults := config.Defaults()

	fmt.Println()
	fmt.Println(titleStyle.Render("Sandbox Summary"))
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("  Name:        %s\n", result.Name)
	fmt.Printf("  Source:      %s\n", result.Source)
	fmt.Printf("  Security:    %s\n", profileName)
	fmt.Printf("  Resources:   %d CPU, %s RAM, %s disk\n", cpu, memory, defaults.VM.Disk)
	fmt.Printf("  Network:     %s\n", getNetworkDescription(result.NetworkLevel))
	fmt.Printf("  Auto-start:  %s\n", boolToYesNo(result.StartAtLogin))
	fmt.Printf("  Config:      %s\n", boolToYesNo(result.SaveConfig)+" (airlock.toml)")
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println()

	// Final action selection
	var action string
	actionOptions := []huh.Option[string]{
		huh.NewOption("✅ Create sandbox now", "create"),
		huh.NewOption("💾 Save config only", "save"),
		huh.NewOption("❌ Cancel", "cancel"),
	}

	if !result.SaveConfig {
		// Remove "Save config only" option if not saving
		actionOptions = actionOptions[:1]
		actionOptions = append(actionOptions, huh.NewOption("❌ Cancel", "cancel"))
	}

	actionForm := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What would you like to do?").
				Options(actionOptions...).
				Value(&action),
		),
	)

	if err := actionForm.Run(); err != nil {
		return nil, err
	}

	switch action {
	case "create":
		result.CreateNow = true
	case "save":
		result.CreateNow = false
	case "cancel":
		return nil, fmt.Errorf("cancelled by user")
	}

	return &result, nil
}

func isValidSandboxName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if !isAlpha(r) && r != '_' {
				return false
			}
		} else {
			if !isAlphaNum(r) && r != '_' && r != '-' && r != '.' {
				return false
			}
		}
	}
	return true
}

func getNetworkDescription(level NetworkLevel) string {
	switch level {
	case NetworkNone:
		return "Locked immediately"
	case NetworkDownloads:
		return "Lock after setup"
	case NetworkOngoing:
		return "Unlocked (ongoing access)"
	default:
		return "Lock after setup"
	}
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// IsTTY returns true if stdout is a terminal.
func IsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
