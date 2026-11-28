// MW006 (medium): the authorization server does not say it returns the iss parameter in
// authorization responses (RFC 9207), so a client talking to several authorization servers cannot
// tell which one answered and is open to mix-up attacks. An absent field means false (RFC 9207
// section 3). Judged only when the authorization server metadata was found.

package check

import "github.com/labibkamran/mcpwarden/internal/probe"

func mw006() Check {
	return Check{
		Rule: Rule{
			ID:       "MW006",
			Title:    "No issuer identification",
			Severity: SeverityMedium,
			OWASP:    owaspAuth,
			Remediation: "Return the iss parameter in authorization responses (RFC 9207) and set " +
				"authorization_response_iss_parameter_supported to true in the authorization server metadata.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			md := ev.AuthServerMetadata
			if md == nil || md.IssParameterSupported {
				return nil
			}
			return []string{"authorization server metadata does not set authorization_response_iss_parameter_supported to true"}
		},
	}
}
