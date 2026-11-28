// FuzzParseURL checks that any accepted URL is http(s), has a host and is already normalized;
// FuzzParseConfig that every config target has a command or url and only http(s) URLs. Run longer
// with: go test -fuzz=FuzzParseURL ./internal/target (or -fuzz=FuzzParseConfig)

package target_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/target"
)

func FuzzParseURL(f *testing.F) {
	seeds := []string{
		"https://mcp.example.com/mcp",
		"HTTP://LOCALHOST:80",
		"http://[::1]:3000/mcp?x=1#frag",
		"https://user:pass@host/",
		"ftp://host",
		"http:opaque",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		got, err := target.ParseURL(raw)
		if err != nil {
			return
		}
		if got.URL.Scheme != "http" && got.URL.Scheme != "https" {
			t.Fatalf("target.ParseURL(%q) accepted scheme %q", raw, got.URL.Scheme)
		}
		if got.URL.Hostname() == "" {
			t.Fatalf("target.ParseURL(%q) accepted an empty host", raw)
		}
		again, err := target.ParseURL(got.String())
		if err != nil {
			t.Fatalf("target.ParseURL(%q) = %q, which no longer parses: %v", raw, got, err)
		}
		if again.String() != got.String() {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, got, again)
		}
	})
}

func FuzzParseConfig(f *testing.F) {
	seeds := []string{
		`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"], "env": {"K": "v"}}}}`,
		`{"servers": {"b": {"type": "http", "url": "https://x.example/mcp", "headers": {"A": "b"}}}}`,
		"{\n// c\n\"servers\": {\"c\": {\"command\": \"x\",},}, /* d */}",
		`{"mcp": {"servers": {"d": {"url": "${input:u}"}}}}`,
		`"str\"ing // not a comment"`,
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		targets, err := target.ParseConfig("fuzz.json", []byte(data))
		if err != nil {
			return
		}
		for _, tgt := range targets {
			if tgt.Server == nil || (tgt.Server.Command == "" && tgt.Server.URL == "") {
				t.Fatalf("ParseConfig(%q) returned a target without a command or url: %+v", data, tgt)
			}
			if tgt.URL != nil && tgt.URL.Scheme != "http" && tgt.URL.Scheme != "https" {
				t.Fatalf("ParseConfig(%q) accepted scheme %q", data, tgt.URL.Scheme)
			}
		}
	})
}
