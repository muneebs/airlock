package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type Phase struct {
	Label     string
	DoneLabel string
	Action    func() error
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func RunPhases(phases []Phase) error {
	for _, p := range phases {
		fmt.Printf("  %s ... ", p.Label)
		os.Stdout.Sync()
		if err := p.Action(); err != nil {
			fmt.Printf("\n  %s %s\n", CrossMark.String(), p.Label)
			return err
		}
		fmt.Printf("\r  %s %s\n", CheckMark.String(), p.DoneLabel)
	}
	return nil
}

func RunSpinner(label, doneLabel string, action func() error) error {
	fmt.Printf("  %s ... ", label)
	os.Stdout.Sync()
	if err := action(); err != nil {
		fmt.Printf("\n  %s %s\n", CrossMark.String(), label)
		return err
	}
	fmt.Printf("\r  %s %s\n", CheckMark.String(), doneLabel)
	return nil
}

var (
	Normal   = lipgloss.NewStyle()
	Bold     = lipgloss.NewStyle().Bold(true)
	Success  = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	SuccessF = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	Error    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	ErrorF   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	WarningF = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))

	Header = lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Bold(true).Underline(true)
	Label  = lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Width(12).Bold(true)
	Value  = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	KeyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Bold(true)

	TableHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252")).Padding(0, 1)
	TableCell   = lipgloss.NewStyle().Padding(0, 1)

	CheckMark = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true).SetString("✓")
	CrossMark = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true).SetString("✗")
	Arrow     = lipgloss.NewStyle().Foreground(lipgloss.Color("69")).SetString("→")
	Bullet    = lipgloss.NewStyle().Foreground(lipgloss.Color("69")).SetString("•")
)

func StateColor(state string) lipgloss.Style {
	switch state {
	case "running":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	case "stopped":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	case "errored":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true)
	}
}

func ProfileColor(profile string) lipgloss.Style {
	switch profile {
	case "strict":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	case "cautious":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	case "dev":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	case "trusted":
		return lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Bold(true)
	default:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	}
}

func LockColor(locked bool) lipgloss.Style {
	if locked {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
}

func CleanError(err error) string {
	msg := err.Error()
	var clean []string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "time=") {
			if idx := strings.Index(line, "msg="); idx != -1 {
				msg := strings.Trim(strings.TrimPrefix(line[idx:], "msg="), `"`)
				if msg != "" {
					clean = append(clean, msg)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "level=") {
			if idx := strings.Index(line, "msg="); idx != -1 {
				msg := strings.Trim(strings.TrimPrefix(line[idx:], "msg="), `"`)
				if msg != "" {
					clean = append(clean, msg)
				}
			}
			continue
		}
		if line != "" {
			clean = append(clean, line)
		}
	}
	if len(clean) == 0 {
		return msg
	}
	return strings.Join(clean, ": ")
}

func init() {
	if isTerminal() {
		lipgloss.SetColorProfile(termenv.EnvColorProfile())
	}
}
