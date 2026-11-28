package check_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/probe"
)

func catalogCheck(t *testing.T, id string) check.Check {
	t.Helper()
	catalog := check.Catalog()
	i := slices.IndexFunc(catalog, func(c check.Check) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("rule %s is not in the catalog", id)
	}
	return catalog[i]
}

func assertSummary(t *testing.T, got []string, want string) {
	t.Helper()
	if want == "" {
		if len(got) != 0 {
			t.Errorf("findings = %q, want none", got)
		}
		return
	}
	if len(got) != 1 || !strings.Contains(got[0], want) {
		t.Errorf("findings = %q, want one containing %q", got, want)
	}
}

func exchange(status int, header ...string) *probe.Exchange {
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Set(header[i], header[i+1])
	}
	return &probe.Exchange{Status: status, Header: h}
}

func fixedCheck(id string, summaries ...string) check.Check {
	return check.Check{
		Rule:     check.Rule{ID: id, Severity: check.SeverityHigh},
		Evaluate: func(*probe.Evidence) []string { return summaries },
	}
}

func TestRunTurnsSummariesIntoFindings(t *testing.T) {
	checks := []check.Check{fixedCheck("MW901", "a", "b"), fixedCheck("MW902"), fixedCheck("MW903", "c")}

	findings, errs := check.Run(checks, &probe.Evidence{})

	if len(errs) != 0 {
		t.Fatalf("errors = %v, want none", errs)
	}
	if got := findingKeys(findings); got != "MW901:a,MW901:b,MW903:c" {
		t.Errorf("findings = %s, want MW901:a,MW901:b,MW903:c", got)
	}
}

func findingKeys(findings []check.Finding) string {
	var keys []string
	for _, f := range findings {
		keys = append(keys, f.Rule.ID+":"+f.Evidence)
	}
	return strings.Join(keys, ",")
}

func TestRunRecoversFromPanickingCheck(t *testing.T) {
	panicking := check.Check{
		Rule:     check.Rule{ID: "MW999"},
		Evaluate: func(ev *probe.Evidence) []string { return []string{ev.ToolsList.Header.Get("x")} },
	}
	checks := []check.Check{panicking, fixedCheck("MW901", "still runs")}

	findings, errs := check.Run(checks, &probe.Evidence{})

	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "check MW999 failed") {
		t.Errorf("errors = %v, want one error naming MW999", errs)
	}
	if len(findings) != 1 || findings[0].Rule.ID != "MW901" {
		t.Errorf("findings = %v, want the other check's finding", findings)
	}
}

func TestRuleDocURL(t *testing.T) {
	got := check.Rule{ID: "MW001"}.DocURL()

	if !strings.HasSuffix(got, "/docs/rules.md#mw001") {
		t.Errorf("DocURL = %q, want it to end with /docs/rules.md#mw001", got)
	}
}
