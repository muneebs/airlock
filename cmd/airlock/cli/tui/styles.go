package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type Phase struct {
	Label     string
	DoneLabel string
	Action    func() error
	// Status, when non-nil, is called on each spinner tick to produce an
	// extra suffix appended to the label (e.g. the current VM lifecycle
	// state). This lets long-running phases give the user live feedback
	// without streaming raw subprocess output. Returning an empty string
	// hides the suffix.
	Status func() string
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// spinnerFrames are braille dots chosen so each frame is a single-width glyph;
// this keeps the \r redraw aligned on all terminals that support UTF-8.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// clearLine erases the current line so the next write starts from column 0
// without leftover glyphs from the previous (usually longer) spinner frame.
const clearLine = "\r\033[2K"

func RunPhases(phases []Phase) error {
	for _, p := range phases {
		if err := runPhase(p); err != nil {
			return err
		}
	}
	return nil
}

// RunSpinner is the simple form kept for callers that don't need a live
// status suffix. Internally it delegates to runPhase.
func RunSpinner(label, doneLabel string, action func() error) error {
	return runPhase(Phase{Label: label, DoneLabel: doneLabel, Action: action})
}

// runPhase drives the action in a goroutine while animating a branded
// spinner on the current line. Each tick redraws the line with the current
// frame, the phase label, elapsed time (so the user can distinguish a slow
// step from a hung one), and an optional Status suffix. When the action
// completes the spinner is replaced with a final check or cross line.
//
// In non-TTY contexts (pipes, CI, JSON output redirects) the spinner would
// emit garbage control sequences, so we fall back to plain start/end lines.
func runPhase(p Phase) error {
	spinnerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	if !isTerminal() {
		fmt.Printf("  %s ...\n", p.Label)
		if err := p.Action(); err != nil {
			fmt.Printf("  %s %s\n", CrossMark.String(), p.Label)
			return err
		}
		fmt.Printf("  %s %s\n", CheckMark.String(), p.DoneLabel)
		return nil
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- p.Action() }()

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	render := func() {
		elapsed := time.Since(start).Round(time.Second)
		suffix := dimStyle.Render(fmt.Sprintf("(%s)", formatElapsed(elapsed)))
		if p.Status != nil {
			if s := p.Status(); s != "" {
				suffix = dimStyle.Render(fmt.Sprintf("(%s · %s)", formatElapsed(elapsed), s))
			}
		}
		fmt.Printf("%s  %s %s %s", clearLine, spinnerStyle.Render(spinnerFrames[frame]), p.Label, suffix)
		_ = os.Stdout.Sync()
	}
	render()

	for {
		select {
		case err := <-done:
			elapsed := time.Since(start).Round(time.Second)
			tail := dimStyle.Render(fmt.Sprintf("(%s)", formatElapsed(elapsed)))
			if err != nil {
				fmt.Printf("%s  %s %s %s\n", clearLine, CrossMark.String(), p.Label, tail)
				return err
			}
			fmt.Printf("%s  %s %s %s\n", clearLine, CheckMark.String(), p.DoneLabel, tail)
			return nil
		case <-ticker.C:
			frame = (frame + 1) % len(spinnerFrames)
			render()
		}
	}
}

// formatElapsed renders a duration as "MM:SS" for anything under an hour
// so the spinner suffix stays a constant width.
func formatElapsed(d time.Duration) string {
	secs := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", secs/60, secs%60)
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
