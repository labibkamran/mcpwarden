package target_test

import (
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/target"
)

func TestParseURLNormalizes(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "keeps a normal url", raw: "https://mcp.example.com/mcp", want: "https://mcp.example.com/mcp"},
		{name: "lowercases scheme and host", raw: "HTTPS://MCP.Example.COM/MCP", want: "https://mcp.example.com/MCP"},
		{name: "removes default https port", raw: "https://mcp.example.com:443/mcp", want: "https://mcp.example.com/mcp"},
		{name: "removes default http port", raw: "http://localhost:80/mcp", want: "http://localhost/mcp"},
		{name: "keeps non-default port", raw: "http://localhost:8080/mcp", want: "http://localhost:8080/mcp"},
		{name: "drops fragment", raw: "https://mcp.example.com/mcp#tools", want: "https://mcp.example.com/mcp"},
		{name: "empty path becomes slash", raw: "https://mcp.example.com", want: "https://mcp.example.com/"},
		{name: "keeps query", raw: "https://mcp.example.com/mcp?tenant=a", want: "https://mcp.example.com/mcp?tenant=a"},
		{name: "trims surrounding space", raw: "  https://mcp.example.com/mcp\n", want: "https://mcp.example.com/mcp"},
		{name: "ipv6 with default port", raw: "https://[::1]:443/mcp", want: "https://[::1]/mcp"},
		{name: "ipv6 with custom port", raw: "http://[::1]:3000/mcp", want: "http://[::1]:3000/mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := target.ParseURL(tt.raw)

			if err != nil {
				t.Fatalf("target.ParseURL(%q) error: %v", tt.raw, err)
			}
			if got.String() != tt.want {
				t.Errorf("target.ParseURL(%q) = %q, want %q", tt.raw, got.String(), tt.want)
			}
		})
	}
}

func TestParseURLRejects(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{name: "empty", raw: "", wantErr: "missing scheme"},
		{name: "no scheme", raw: "mcp.example.com/mcp", wantErr: "missing scheme"},
		{name: "ftp scheme", raw: "ftp://mcp.example.com", wantErr: `unsupported scheme "ftp"`},
		{name: "file scheme", raw: "file:///etc/passwd", wantErr: `unsupported scheme "file"`},
		{name: "no host", raw: "https:///mcp", wantErr: "missing host"},
		{name: "opaque url", raw: "http:mcp", wantErr: "missing host"},
		{name: "port zero", raw: "http://localhost:0/", wantErr: "invalid port"},
		{name: "port too large", raw: "http://localhost:70000/", wantErr: "invalid port"},
		{name: "bad escape", raw: "http://localhost/%zz", wantErr: "invalid url"},
		{name: "space in query", raw: "http://00? #", wantErr: "contains whitespace"},
		{name: "space in path", raw: "https://mcp.example.com/a b", wantErr: "contains whitespace"},
		{name: "credentials", raw: "https://user:pass@mcp.example.com/", wantErr: "credentials in the url"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := target.ParseURL(tt.raw)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("target.ParseURL(%q) error = %v, want it to contain %q", tt.raw, err, tt.wantErr)
			}
		})
	}
}

func TestParseURLErrorsDoNotLeakCredentials(t *testing.T) {
	inputs := []string{
		"https://user:s3cret@mcp.example.com/",
		"https://user:s3cret@mcp.example.com/%zz",
	}

	for _, raw := range inputs {
		_, err := target.ParseURL(raw)

		if err == nil || strings.Contains(err.Error(), "s3cret") {
			t.Errorf("target.ParseURL(%q) error = %v, want an error without the password", raw, err)
		}
	}
}
