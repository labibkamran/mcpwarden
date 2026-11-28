// MW003 (medium): the CORS preflight lets any web page call the server from a browser, either with
// Access-Control-Allow-Origin: * or by echoing the foreign Origin back, which is worse because it
// also works with credentials (FR-009).

package check

import (
	"fmt"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw003() Check {
	return Check{
		Rule: Rule{
			ID:          "MW003",
			Title:       "Wildcard CORS",
			Severity:    SeverityMedium,
			OWASP:       owaspAuth,
			Remediation: "Answer CORS preflights only for known origins, never with * or by echoing the request's Origin.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			if ev.Preflight == nil {
				return nil
			}
			switch ev.Preflight.Header.Get("Access-Control-Allow-Origin") {
			case "*":
				return []string{"CORS preflight answered Access-Control-Allow-Origin: *"}
			case probe.ForeignOrigin:
				return []string{fmt.Sprintf("CORS preflight echoed Origin %s in Access-Control-Allow-Origin", probe.ForeignOrigin)}
			default:
				return nil
			}
		},
	}
}
