// MW010 (high): the server is reached over plain http on a host that is not this machine, so
// tokens and tool results cross the network unencrypted and can be read or changed on the way.
// localhost, *.localhost and loopback addresses are exempt: that traffic never leaves the host.
// It applies to URL arguments and config entries alike, and needs no probe, so it is reported
// even when the server is unreachable. A config url that cannot be parsed is not judged.

package check

import (
	"net"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func mw010() Check {
	return Check{
		Rule: Rule{
			ID:          "MW010",
			Title:       "Plain HTTP endpoint",
			Severity:    SeverityHigh,
			OWASP:       owaspExposure,
			Remediation: "Serve the endpoint over HTTPS (TLS 1.2 or later) and point clients at the https:// URL.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			u := ev.Target.URL
			if u == nil || u.Scheme != "http" || isLocalHost(u.Hostname()) {
				return nil
			}
			return []string{"the endpoint uses http:// on " + u.Hostname() + ", which is not this machine"}
		},
	}
}

func isLocalHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	host = strings.ToLower(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}
