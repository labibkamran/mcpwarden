// Package check holds the security rules (MW001–MW012) and the types they share (FR-015 to
// FR-017). A Check pairs a Rule's metadata with a pure Evaluate function: evidence in, one summary
// per finding out, no I/O. Catalog lists every rule; adding one means a new file, its test and a
// line in Catalog, with no engine change (NFR-014). Run recovers a check that panics, reports it
// as an error and carries on with the others (NFR-012). OWASP labels refer to the OWASP MCP Top 10
// (2025, beta); DocURL points at the rule's section in docs/rules.md (NFR-013).
package check

import (
	"fmt"
	"slices"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

const (
	docsURL   = "https://github.com/labibkamran/mcpwarden/blob/main/docs/rules.md#"
	owaspAuth = "MCP07:2025 Insufficient Authentication & Authorization"
)

type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	OWASP       string
	Remediation string
}

func (r Rule) DocURL() string {
	return docsURL + strings.ToLower(r.ID)
}

type Check struct {
	Rule
	Evaluate func(ev *probe.Evidence) []string
}

type Finding struct {
	Rule     Rule
	Evidence string
}

func Catalog() []Check {
	return []Check{mw001(), mw002(), mw003(), mw004(), mw005()}
}

func Select(sel RuleSelection) []Check {
	var checks []Check
	for _, c := range Catalog() {
		if !slices.Contains(sel.Disable, c.ID) {
			checks = append(checks, c)
		}
	}
	return checks
}

func Run(checks []Check, ev *probe.Evidence) ([]Finding, []error) {
	var findings []Finding
	var errs []error
	for _, c := range checks {
		summaries, err := evaluate(c, ev)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, s := range summaries {
			findings = append(findings, Finding{Rule: c.Rule, Evidence: s})
		}
	}
	return findings, errs
}

func evaluate(c Check, ev *probe.Evidence) (summaries []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("check %s failed: %v", c.ID, r)
		}
	}()
	return c.Evaluate(ev), nil
}
