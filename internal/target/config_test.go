package target_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/target"
)

func TestParseConfigFormats(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "claude desktop",
			data: `{"mcpServers": {"files": {"command": "npx", "args": ["-y", "server-files"]}}}`,
			want: []string{"cfg.json: files"},
		},
		{
			name: "cursor remote server",
			data: `{"mcpServers": {"remote": {"url": "HTTPS://MCP.Example.com/mcp"}}}`,
			want: []string{"cfg.json: remote (https://mcp.example.com/mcp)"},
		},
		{
			name: "vs code with comments and trailing commas",
			data: `{
				// workspace servers
				"servers": {
					"api": {"type": "http", "url": "https://api.example.com//mcp", /* doubled slash */},
				},
			}`,
			want: []string{"cfg.json: api (https://api.example.com//mcp)"},
		},
		{
			name: "vs code settings.json",
			data: `{"editor.tabSize": 2, "mcp": {"servers": {"local": {"command": "node", "args": ["server.js"]}}}}`,
			want: []string{"cfg.json: local"},
		},
		{
			name: "entries sorted by name",
			data: `{"mcpServers": {"zeta": {"command": "z"}, "alpha": {"command": "a"}}}`,
			want: []string{"cfg.json: alpha", "cfg.json: zeta"},
		},
		{
			name: "unterminated comment at the end",
			data: `{"mcpServers": {"a": {"command": "x"}}} /* open`,
			want: []string{"cfg.json: a"},
		},
		{
			name: "url built from a variable is kept but not probed",
			data: `{"servers": {"vars": {"type": "http", "url": "${input:host}/mcp"}}}`,
			want: []string{"cfg.json: vars"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := target.ParseConfig("cfg.json", []byte(tt.data))

			if err != nil {
				t.Fatalf("ParseConfig error: %v", err)
			}
			var got []string
			for _, tgt := range targets {
				got = append(got, tgt.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("targets = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseConfigKeepsTheEntry(t *testing.T) {
	data := `{"mcpServers": {"db": {
		"command": "uvx", "args": ["db-server"],
		"env": {"DB_URL": "postgres://db", "PORT": 5432, "UNSET": null},
		"url": "${env:DB_HOST}", "headers": {"X-Team": "core"}
	}}}`

	targets, err := target.ParseConfig("cfg.json", []byte(data))

	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}
	srv := targets[0].Server
	wantEnv := map[string]string{"DB_URL": "postgres://db", "PORT": "5432"}
	if srv.Command != "uvx" || !slices.Equal(srv.Args, []string{"db-server"}) || !maps.Equal(srv.Env, wantEnv) ||
		srv.URL != "${env:DB_HOST}" || srv.Headers["X-Team"] != "core" || targets[0].URL != nil {
		t.Errorf("server = %+v, URL = %v; want the entry as written, env as strings and no parsed URL", srv, targets[0].URL)
	}
}

func TestParseConfigRejects(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{name: "empty file", data: "", wantErr: "invalid JSON on line 1"},
		{name: "syntax error line", data: "{\n\"mcpServers\": {\n\"a\": {\"command\": \"x\" \"y\"}}}", wantErr: "invalid JSON on line 3"},
		{name: "no servers", data: `{"other": {}}`, wantErr: "no MCP servers found"},
		{name: "entry without command or url", data: `{"mcpServers": {"empty": {}}}`, wantErr: `server "empty": want "command" or "url"`},
		{name: "wrong shape", data: `{"mcpServers": {"a": {"command": "x", "args": "not-a-list"}}}`, wantErr: "unexpected config shape"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := target.ParseConfig("cfg.json", []byte(tt.data))

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseConfig error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseConfigErrorsNeverQuoteValues(t *testing.T) {
	data := `{"mcpServers": {"a": {"command": "x", "headers": {"Authorization": ["Bearer sk-secret-value"]}}}}`

	_, err := target.ParseConfig("cfg.json", []byte(data))

	if err == nil || strings.Contains(err.Error(), "sk-secret-value") {
		t.Errorf("ParseConfig error = %v, want an error without the value", err)
	}
}
