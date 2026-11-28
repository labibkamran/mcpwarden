// MW002 (high): the server accepts a request from a foreign Origin, so a malicious web page can
// reach it through DNS rebinding. MCP 2026-07-28 requires 403 for an invalid Origin, so any 2xx to
// the foreign-origin tools/list is a finding (FR-008). A 401 proves nothing, because the auth
// check may run first; a token passed with --header lets the probe get past it.

package check

import (
	"fmt"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw002() Check {
	return Check{
		Rule: Rule{
			ID:          "MW002",
			Title:       "Host/Origin not validated (DNS rebinding)",
			Severity:    SeverityHigh,
			OWASP:       owaspAuth,
			Remediation: "Answer 403 to any request whose Origin is not on an allow-list, and bind local servers to 127.0.0.1.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			if !ev.ForeignOrigin.Succeeded() {
				return nil
			}
			return []string{fmt.Sprintf("tools/list with Origin: %s returned %d instead of 403", probe.ForeignOrigin, ev.ForeignOrigin.Status)}
		},
	}
}
