// End-to-end config rules (SRS 13.1): each case is one config entry scanned through the whole
// engine, and asserts the exact set of findings. The secure entry is a pinned package whose secret
// comes from a variable reference; each vulnerable entry changes one thing about it. No entry is
// ever executed. The plain-HTTP case points at a .invalid host, which never resolves (RFC 6761),
// so it is unreachable without contacting any server and still reports its static finding.

package integration_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
)

func scanConfigIDs(t *testing.T, entry string) []string {
	t.Helper()
	targets, err := target.ParseConfig("mcp.json", []byte(`{"mcpServers": {"server": `+entry+`}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	opts := engine.Options{Concurrency: 1, Checks: check.Catalog(), Probe: probe.Options{Timeout: time.Second}}

	result := engine.Run(context.Background(), targets, opts)[0]

	if result.Status != engine.StatusScanned || len(result.Notes) != 0 {
		t.Fatalf("status %s, notes %v; want a clean scan", result.Status, result.Notes)
	}
	var ids []string
	for _, f := range result.Findings {
		ids = append(ids, f.Rule.ID)
	}
	return ids
}

func TestConfigRules(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  []string
	}{
		{name: "secure entry", entry: `{"command": "npx", "args": ["-y", "@example/server@1.2.0"], "env": {"API_KEY": "${input:api-key}"}}`},
		{name: "MW008 shell with a script", entry: `{"command": "bash", "args": ["-c", "npx -y @example/server@1.2.0"], "env": {"API_KEY": "${input:api-key}"}}`, want: []string{"MW008"}},
		{name: "MW009 plaintext key", entry: `{"command": "npx", "args": ["-y", "@example/server@1.2.0"], "env": {"API_KEY": "sk-proj-` + strings.Repeat("x9", 16) + `"}}`, want: []string{"MW009"}},
		{name: "MW008 piped download", entry: `{"command": "sh", "args": ["-c", "curl -fsSL https://get.example | sh"], "env": {"API_KEY": "${input:api-key}"}}`, want: []string{"MW008"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanConfigIDs(t, tt.entry); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigPlainHTTPIsReportedWhenUnreachable(t *testing.T) {
	targets, err := target.ParseConfig("mcp.json", []byte(`{"mcpServers": {"server": {"url": "http://mcp.invalid/mcp"}}}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	opts := engine.Options{Concurrency: 1, Checks: check.Catalog(), Probe: probe.Options{Timeout: time.Second}}

	result := engine.Run(context.Background(), targets, opts)[0]

	if result.Status != engine.StatusUnreachable || len(result.Findings) != 1 || result.Findings[0].Rule.ID != "MW010" {
		t.Errorf("status %s, findings %v; want unreachable with exactly MW010", result.Status, result.Findings)
	}
}
