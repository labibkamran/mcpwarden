// MW011 (high, opt-in): in authenticated mode the server accepted a token whose aud claim names
// another resource, so a token issued for any service on the same authorization server works here
// too (RFC 8707, RFC 9068 section 4). It needs a JWT from the user (--header); an opaque token has
// no readable audience and is not judged. The audience matches when it equals the resource in the
// protected resource metadata, the target URL, or either one's origin, ignoring a trailing slash,
// because authorization servers differ in which of these they issue. Opt-in, because it judges a
// token the user chose rather than the server alone.

package check

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw011() Check {
	return Check{
		Rule: Rule{
			ID:       "MW011",
			Title:    "Token audience not bound",
			Severity: SeverityHigh,
			OWASP:    owaspAuth,
			OptIn:    true,
			Remediation: "Accept only tokens whose aud claim names this server's resource, and have clients " +
				"request them with an RFC 8707 resource indicator.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			if !ev.AuthToolsListed || !ev.AuthToolsList.Succeeded() || len(ev.TokenAudience) == 0 || ev.Target.URL == nil {
				return nil
			}
			own := ownAudiences(ev)
			if slices.ContainsFunc(ev.TokenAudience, func(aud string) bool { return slices.Contains(own, trimSlash(aud)) }) {
				return nil
			}
			return []string{fmt.Sprintf("tools/list accepted a token for audience [%s], not this server's resource %s",
				strings.Join(ev.TokenAudience, ", "), own[0])}
		},
	}
}

func ownAudiences(ev *probe.Evidence) []string {
	var resources []string
	if ev.ResourceMetadata != nil && ev.ResourceMetadata.Resource != "" {
		resources = append(resources, ev.ResourceMetadata.Resource)
	}
	resources = append(resources, ev.Target.URL.String())
	var own []string
	for _, r := range resources {
		own = append(own, trimSlash(r))
		if u, err := url.Parse(r); err == nil && u.Host != "" {
			own = append(own, u.Scheme+"://"+u.Host)
		}
	}
	return own
}

func trimSlash(s string) string {
	return strings.TrimSuffix(s, "/")
}
