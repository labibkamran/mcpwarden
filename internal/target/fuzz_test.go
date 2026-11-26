package target

import "testing"

// FuzzParseURL checks that any accepted URL is http(s), has a host, and is
// already normalized: parsing its string form again yields the same string.
// Run longer with: go test -fuzz=FuzzParseURL ./internal/target
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
		got, err := ParseURL(raw)
		if err != nil {
			return
		}
		if got.URL.Scheme != "http" && got.URL.Scheme != "https" {
			t.Fatalf("ParseURL(%q) accepted scheme %q", raw, got.URL.Scheme)
		}
		if got.URL.Hostname() == "" {
			t.Fatalf("ParseURL(%q) accepted an empty host", raw)
		}
		again, err := ParseURL(got.String())
		if err != nil {
			t.Fatalf("ParseURL(%q) = %q, which no longer parses: %v", raw, got, err)
		}
		if again.String() != got.String() {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, got, again)
		}
	})
}
