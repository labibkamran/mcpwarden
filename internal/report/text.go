// Package report writes scan results (FR-020). Text is the terminal format: one block per target
// with its grade, or the reason it was unreachable or is not an MCP endpoint; each finding with its
// evidence, a fix in plain words and a documentation link (NFR-013); notes about probes that
// failed; then a one-line summary. JSON and SARIF arrive in milestone 4. Writes go through
// errWriter, so a full disk or a closed pipe is reported once instead of being ignored.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
)

type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err == nil {
		_, ew.err = fmt.Fprintf(ew.w, format, args...)
	}
}

func Text(w io.Writer, results []engine.Result) error {
	ew := &errWriter{w: w}
	for _, r := range results {
		writeResult(ew, r)
	}
	writeSummary(ew, results)
	return ew.err
}

func writeResult(ew *errWriter, r engine.Result) {
	ew.printf("%s\n", r.Target)
	switch r.Status {
	case engine.StatusUnreachable:
		ew.printf("  Unreachable: %v\n\n", r.Err)
		return
	case engine.StatusNotMCP:
		ew.printf("  Not an MCP endpoint: %v\n\n", r.Err)
		return
	}
	ew.printf("  Grade %s · %s\n", r.Grade, plural(len(r.Findings), "finding"))
	for _, f := range r.Findings {
		ew.printf("\n  %-8s  %s  %s\n", strings.ToUpper(f.Rule.Severity.String()), f.Rule.ID, f.Rule.Title)
		ew.printf("            %s\n", f.Evidence)
		ew.printf("            Fix:  %s\n", f.Rule.Remediation)
		ew.printf("            Docs: %s\n", f.Rule.DocURL())
	}
	for _, note := range r.Notes {
		ew.printf("\n  Note: %v\n", note)
	}
	ew.printf("\n")
}

func writeSummary(ew *errWriter, results []engine.Result) {
	statuses, counts, total := map[engine.Status]int{}, map[check.Severity]int{}, 0
	for _, r := range results {
		statuses[r.Status]++
		for _, f := range r.Findings {
			counts[f.Rule.Severity]++
			total++
		}
	}
	ew.printf("%s: %d scanned, %d unreachable", plural(len(results), "target"),
		statuses[engine.StatusScanned], statuses[engine.StatusUnreachable])
	if n := statuses[engine.StatusNotMCP]; n > 0 {
		ew.printf(", %d not MCP", n)
	}
	ew.printf(" · %s", plural(total, "finding"))
	if breakdown := severityBreakdown(counts); breakdown != "" {
		ew.printf(" (%s)", breakdown)
	}
	ew.printf("\n")
}

func severityBreakdown(counts map[check.Severity]int) string {
	var parts []string
	for _, s := range []check.Severity{check.SeverityCritical, check.SeverityHigh, check.SeverityMedium, check.SeverityLow} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
