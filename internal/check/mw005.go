// MW005 (high): the authorization server does not advertise PKCE with S256, so a stolen
// authorization code can be redeemed. MCP 2026-07-28 tells clients to refuse an authorization
// server whose metadata lacks code_challenge_methods_supported. Judged only when that metadata was
// found; whether it can be found at all is MW004's concern.

package check

import (
	"fmt"
	"slices"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw005() Check {
	return Check{
		Rule: Rule{
			ID:          "MW005",
			Title:       "PKCE S256 not advertised",
			Severity:    SeverityHigh,
			OWASP:       owaspAuth,
			Remediation: "Support PKCE with S256 on the authorization server and list it in code_challenge_methods_supported.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			md := ev.AuthServerMetadata
			if md == nil || slices.Contains(md.CodeChallengeMethodsSupported, "S256") {
				return nil
			}
			if len(md.CodeChallengeMethodsSupported) == 0 {
				return []string{"authorization server metadata has no code_challenge_methods_supported"}
			}
			return []string{fmt.Sprintf("code_challenge_methods_supported is [%s], without S256",
				strings.Join(md.CodeChallengeMethodsSupported, ", "))}
		},
	}
}
