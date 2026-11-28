package check_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
)

func TestMW010(t *testing.T) {
	at := func(raw string) probe.Evidence {
		tgt, err := target.ParseURL(raw)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		return probe.Evidence{Target: tgt}
	}
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "remote host over http", ev: at("http://mcp.example.com/mcp"), want: "uses http:// on mcp.example.com"},
		{name: "private address over http", ev: at("http://10.0.0.5:8080/mcp"), want: "uses http:// on 10.0.0.5"},
		{name: "https", ev: at("https://mcp.example.com/mcp")},
		{name: "localhost", ev: at("http://localhost:3000/mcp")},
		{name: "localhost subdomain", ev: at("http://mcp.localhost/mcp")},
		{name: "ipv4 loopback", ev: at("http://127.0.0.2:3000/mcp")},
		{name: "ipv6 loopback", ev: at("http://[::1]:3000/mcp")},
		{name: "stdio entry", ev: withCommand("npx")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW010").Evaluate(&tt.ev), tt.want)
		})
	}
}
