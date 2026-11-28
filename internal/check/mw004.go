// MW004 (medium): the server demands authentication but publishes no RFC 9728 protected resource
// metadata, so clients cannot discover its authorization server. It applies only when the
// unauthenticated tools/list got 401 or 403 (an open server is already MW001) and every metadata
// location answered without a document, so a network failure never counts as missing.

package check

import (
	"fmt"
	"net/http"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw004() Check {
	return Check{
		Rule: Rule{
			ID:       "MW004",
			Title:    "Missing protected resource metadata",
			Severity: SeverityMedium,
			OWASP:    owaspAuth,
			Remediation: "Publish RFC 9728 protected resource metadata at /.well-known/oauth-protected-resource " +
				"and point to it from the resource_metadata parameter of the 401's WWW-Authenticate header.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			status := ev.ToolsList.Status
			demandsAuth := status == http.StatusUnauthorized || status == http.StatusForbidden
			if !demandsAuth || !ev.ResourceMetadataMissing {
				return nil
			}
			return []string{fmt.Sprintf("tools/list returned %d but no protected resource metadata was found "+
				"through WWW-Authenticate or /.well-known/oauth-protected-resource", status)}
		},
	}
}
