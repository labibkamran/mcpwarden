package report_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
	"github.com/labibkamran/mcpwarden/internal/report"
	"github.com/labibkamran/mcpwarden/internal/target"
)

func mustTarget(t *testing.T, raw string) target.Target {
	t.Helper()
	tgt, err := target.ParseURL(raw)
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return tgt
}

var plainHTTP = check.Rule{
	ID:          "MW010",
	Title:       "Plain HTTP endpoint",
	Severity:    check.SeverityHigh,
	Remediation: "Serve the endpoint over HTTPS.",
}

func sampleResults(t *testing.T) []engine.Result {
	rule := check.Rule{
		ID:          "MW001",
		Title:       "No authentication required",
		Severity:    check.SeverityCritical,
		Remediation: "Require OAuth 2.1 bearer tokens.",
	}
	return []engine.Result{
		{
			Target:   mustTarget(t, "https://open.example/mcp"),
			Status:   engine.StatusScanned,
			Grade:    "D",
			Findings: []check.Finding{{Rule: rule, Evidence: "tools/list returned 200 with 2 tools and no token"}},
			Notes:    []error{errors.New("CORS preflight: connection reset")},
		},
		{
			Target:   mustTarget(t, "http://down.example/mcp"),
			Status:   engine.StatusUnreachable,
			Err:      errors.New("tools/list: connection refused"),
			Findings: []check.Finding{{Rule: plainHTTP, Evidence: "the url uses http:// on a non-local host"}},
		},
		{
			Target: mustTarget(t, "https://site.example/"),
			Status: engine.StatusNotMCP,
			Err:    errors.New("tools/list got HTTP 404 (text/html) instead of an MCP response"),
		},
		{
			Target: mustTarget(t, "https://safe.example/mcp"),
			Status: engine.StatusScanned,
			Grade:  "A",
		},
	}
}

func TestText(t *testing.T) {
	var out bytes.Buffer

	err := report.Text(&out, sampleResults(t))

	if err != nil {
		t.Fatalf("Text error: %v", err)
	}
	want := `https://open.example/mcp
  Grade D · 1 finding

  CRITICAL  MW001  No authentication required
            tools/list returned 200 with 2 tools and no token
            Fix:  Require OAuth 2.1 bearer tokens.
            Docs: https://github.com/labibkamran/mcpwarden/blob/main/docs/rules.md#mw001

  Note: CORS preflight: connection reset

http://down.example/mcp
  Unreachable: tools/list: connection refused

  HIGH      MW010  Plain HTTP endpoint
            the url uses http:// on a non-local host
            Fix:  Serve the endpoint over HTTPS.
            Docs: https://github.com/labibkamran/mcpwarden/blob/main/docs/rules.md#mw010

https://site.example/
  Not an MCP endpoint: tools/list got HTTP 404 (text/html) instead of an MCP response

https://safe.example/mcp
  Grade A · 0 findings

4 targets: 2 scanned, 1 unreachable, 1 not MCP · 2 findings (1 critical, 1 high)
`
	if out.String() != want {
		t.Errorf("report =\n%s\nwant\n%s", out.String(), want)
	}
}

type failingWriter struct{ writes int }

func (w *failingWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("disk full")
}

func TestTextReportsTheFirstWriteError(t *testing.T) {
	w := &failingWriter{}

	err := report.Text(w, sampleResults(t))

	if err == nil || err.Error() != "disk full" || w.writes != 1 {
		t.Errorf("error = %v after %d writes, want \"disk full\" after 1", err, w.writes)
	}
}
