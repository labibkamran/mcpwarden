// MW012 (medium, opt-in): the protected resource metadata offers a single scope while the token
// lists several tools, so one grant unlocks every tool and a client cannot ask for less than all
// of them, against least privilege. It needs authenticated mode (--header) and scopes_supported in
// the metadata; an absent list is not judged, since RFC 9728 makes it optional. Opt-in, because a server may still check finer permissions inside each tool.

package check

import (
	"fmt"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

const minToolsForScopes = 2

func mw012() Check {
	return Check{
		Rule: Rule{
			ID:       "MW012",
			Title:    "No per-tool scopes",
			Severity: SeverityMedium,
			OWASP:    owaspScopes,
			OptIn:    true,
			Remediation: "Define least-privilege scopes (for example read and write per resource), list them in " +
				"scopes_supported, and check them on every tool call.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			md := ev.ResourceMetadata
			if !ev.AuthToolsListed || !ev.AuthToolsList.Succeeded() || len(ev.AuthTools) < minToolsForScopes ||
				md == nil || len(md.ScopesSupported) != 1 {
				return nil
			}
			return []string{fmt.Sprintf("protected resource metadata offers one scope (%s) and the token lists %d tools",
				md.ScopesSupported[0], len(ev.AuthTools))}
		},
	}
}
