// The list-checks command (FR-001): one aligned row per rule in the catalog with its ID, severity
// and title, opt-in rules marked with the flag that turns them on, followed by where each rule is
// documented.

package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/labibkamran/mcpwarden/internal/check"
)

func listChecks(stdout, stderr io.Writer) int {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tTITLE")
	for _, c := range check.Catalog() {
		title := c.Title
		if c.OptIn {
			title += " (opt-in: --enable " + c.ID + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.ID, c.Severity, title)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "mcpwarden list-checks: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "\nDetails and fixes: %s\n", projectURL+"/blob/main/docs/rules.md")
	return ExitOK
}
