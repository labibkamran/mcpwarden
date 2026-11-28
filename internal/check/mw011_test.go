package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
)

func TestMW011(t *testing.T) {
	tgt, err := target.ParseURL("https://mcp.example.com/mcp")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	accepted := func(status int, audience ...string) probe.Evidence {
		return probe.Evidence{Target: tgt, AuthToolsList: exchange(status), AuthToolsListed: true, TokenAudience: audience}
	}
	withResource := accepted(http.StatusOK, "https://api.example.com/v1")
	withResource.ResourceMetadata = &probe.ResourceMetadata{Resource: "https://api.example.com/v1/"}
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "other audience accepted", ev: accepted(http.StatusOK, "https://other.example/mcp"),
			want: "accepted a token for audience [https://other.example/mcp], not this server's resource https://mcp.example.com/mcp"},
		{name: "audience is the target url", ev: accepted(http.StatusOK, "https://mcp.example.com/mcp/")},
		{name: "audience is the origin", ev: accepted(http.StatusOK, "https://mcp.example.com")},
		{name: "one of several audiences matches", ev: accepted(http.StatusOK, "https://other.example", "https://mcp.example.com/mcp")},
		{name: "audience is the published resource", ev: withResource},
		{name: "token rejected", ev: accepted(http.StatusUnauthorized, "https://other.example/mcp")},
		{name: "opaque token", ev: accepted(http.StatusOK)},
		{name: "no authenticated mode", ev: probe.Evidence{Target: tgt}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW011").Evaluate(&tt.ev), tt.want)
		})
	}
}
