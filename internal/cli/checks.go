// The list-checks command (FR-001): one aligned row per rule in the catalog with its ID, severity
// and title, followed by where each rule is documented.

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
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.ID, c.Severity, c.Title)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "mcpwarden list-checks: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "\nDetails and fixes: %s\n", projectURL+"/blob/main/docs/rules.md")
	return ExitOK
}
