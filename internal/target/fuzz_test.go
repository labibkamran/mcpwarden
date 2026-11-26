// FuzzParseURL checks that any accepted URL is http(s), has a host and is already
// normalized. Run longer with: go test -fuzz=FuzzParseURL ./internal/target

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
