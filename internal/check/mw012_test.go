package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW012(t *testing.T) {
	authenticated := func(status int, tools int, scopes ...string) probe.Evidence {
		return probe.Evidence{
			AuthToolsList:    exchange(status),
			AuthToolsListed:  true,
			AuthTools:        make([]probe.Tool, tools),
			ResourceMetadata: &probe.ResourceMetadata{ScopesSupported: scopes},
		}
	}
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "one scope for several tools", ev: authenticated(http.StatusOK, 3, "admin"), want: "offers one scope (admin) and the token lists 3 tools"},
		{name: "several scopes", ev: authenticated(http.StatusOK, 3, "read", "write")},
		{name: "one tool", ev: authenticated(http.StatusOK, 1, "admin")},
		{name: "scopes not published", ev: authenticated(http.StatusOK, 3)},
		{name: "token rejected", ev: authenticated(http.StatusUnauthorized, 0, "admin")},
		{name: "no authenticated mode", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW012").Evaluate(&tt.ev), tt.want)
		})
	}
}
