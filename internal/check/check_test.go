package check_test

import (
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/probe"
)

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
