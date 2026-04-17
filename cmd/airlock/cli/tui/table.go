package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type TableColumn struct {
	Header string
	Width  int
}

type Table struct {
	columns []TableColumn
	rows    [][]string
	width   int
}

func NewTable(columns ...TableColumn) *Table {
	return &Table{columns: columns}
}

func (t *Table) AddRow(values ...string) *Table {
	t.rows = append(t.rows, values)
	return t
}

func (t *Table) Render() string {
	var b strings.Builder

	var headers []string
	for _, col := range t.columns {
		if col.Width > 0 {
			headers = append(headers, TableHeader.Width(col.Width).Render(col.Header))
		} else {
			headers = append(headers, TableHeader.Render(col.Header))
		}
	}
	b.WriteString(strings.Join(headers, ""))
	b.WriteString("\n")

	for _, row := range t.rows {
		var cells []string
		for i, val := range row {
			style := TableCell
			if i < len(t.columns) && t.columns[i].Width > 0 {
				style = style.Width(t.columns[i].Width)
			}
			cells = append(cells, style.Render(val))
		}
		b.WriteString(strings.Join(cells, ""))
		b.WriteString("\n")
	}

	return b.String()
}

func InfoLine(format string, args ...any) string {
	return Arrow.String() + " " + fmt.Sprintf(format, args...)
}

func SuccessLine(format string, args ...any) string {
	return CheckMark.String() + " " + SuccessF.Render(fmt.Sprintf(format, args...))
}

func ErrorLine(format string, args ...any) string {
	return CrossMark.String() + " " + ErrorF.Render(fmt.Sprintf(format, args...))
}

func WarningLine(format string, args ...any) string {
	return fmt.Sprintf("⚠ "+format, args...)
}

func KeyValueLine(key, value string) string {
	return Label.Render(key+":") + " " + Value.Render(value)
}

func SectionHeader(title string) string {
	return Header.Render(title)
}

func EmptyState(msg string) string {
	return lipgloss.NewStyle().Italic(true).Faint(true).Render(msg)
}

func StyledKeyValue(key string, value string, keyStyle lipgloss.Style) string {
	return keyStyle.Width(12).Render(key+":") + " " + Value.Render(value)
}
