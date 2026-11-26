package cli_test

import (
	"slices"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/cli"
)

func TestScanFlagsAndURLsInAnyOrder(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantURLs   []string
		wantFormat string
	}{
		{name: "flags first", args: []string{"--format", "json", "https://a/"}, wantURLs: []string{"https://a/"}, wantFormat: "json"},
		{name: "flags last", args: []string{"https://a/", "--format", "json"}, wantURLs: []string{"https://a/"}, wantFormat: "json"},
		{name: "flags between", args: []string{"https://a/", "-format=json", "https://b/"}, wantURLs: []string{"https://a/", "https://b/"}, wantFormat: "json"},
		{name: "repeated flag around a url", args: []string{"--header", "A: 1", "https://a/", "--header", "B: 2"}, wantURLs: []string{"https://a/"}, wantFormat: "text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := cli.ParseScanArgs(tt.args)

			if err != nil {
				t.Fatalf("ParseScanArgs error: %v", err)
			}
			if got := targetStrings(opts); !slices.Equal(got, tt.wantURLs) {
				t.Errorf("Targets = %q, want %q", got, tt.wantURLs)
			}
			if opts.Format != tt.wantFormat {
				t.Errorf("Format = %q, want %q", opts.Format, tt.wantFormat)
			}
		})
	}
}

func TestScanRepeatedHeadersAreAllKept(t *testing.T) {
	opts, err := cli.ParseScanArgs([]string{"--header", "A: 1", "https://a/", "--header", "B: 2"})

	if err != nil {
		t.Fatalf("ParseScanArgs error: %v", err)
	}
	if opts.Headers.Get("A") != "1" || opts.Headers.Get("B") != "2" {
		t.Errorf("Headers = %v, want A: 1 and B: 2", opts.Headers)
	}
}

func targetStrings(opts cli.ScanOptions) []string {
	var urls []string
	for _, t := range opts.Targets {
		urls = append(urls, t.String())
	}
	return urls
}
