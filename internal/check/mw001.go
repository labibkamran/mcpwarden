// MW001 (critical): the server lists its tools to a client that sent no token. Evidence is a 2xx
// answer to the unauthenticated tools/list probe that carries a JSON-RPC result (FR-007); an empty
// tool list still counts, because the endpoint itself is open.

package check

import (
	"fmt"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw001() Check {
	return Check{
		Rule: Rule{
			ID:          "MW001",
			Title:       "No authentication required",
			Severity:    SeverityCritical,
			OWASP:       owaspAuth,
			Remediation: "Require OAuth 2.1 bearer tokens on every request and answer 401 without one.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			if !ev.ToolsListed || !ev.ToolsList.Succeeded() {
				return nil
			}
			return []string{fmt.Sprintf("tools/list returned %d with %d tools and no token", ev.ToolsList.Status, len(ev.Tools))}
		},
	}
}
