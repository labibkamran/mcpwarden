package main

import (
	"flag"
	"io"
	"slices"
	"testing"
)

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		wantPositional []string
		wantFormat     string
		wantHeaders    []string
	}{
		{name: "flags first", args: []string{"--format", "json", "https://a"}, wantPositional: []string{"https://a"}, wantFormat: "json"},
		{name: "flags last", args: []string{"https://a", "--format", "json"}, wantPositional: []string{"https://a"}, wantFormat: "json"},
		{name: "flags between", args: []string{"https://a", "-format=json", "https://b"}, wantPositional: []string{"https://a", "https://b"}, wantFormat: "json"},
		{name: "repeated flag keeps order", args: []string{"--header", "A: 1", "x", "--header", "B: 2"}, wantPositional: []string{"x"}, wantHeaders: []string{"A: 1", "B: 2"}},
		{name: "no args", args: nil, wantPositional: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			format := fs.String("format", "", "")
			var headers stringList
			fs.Var(&headers, "header", "")

			got, err := parseInterspersed(fs, tt.args)

			if err != nil {
				t.Fatalf("parseInterspersed error: %v", err)
			}
			if !slices.Equal(got, tt.wantPositional) {
				t.Errorf("positional = %q, want %q", got, tt.wantPositional)
			}
			if *format != tt.wantFormat {
				t.Errorf("format = %q, want %q", *format, tt.wantFormat)
			}
			if !slices.Equal(headers, tt.wantHeaders) {
				t.Errorf("headers = %q, want %q", headers, tt.wantHeaders)
			}
		})
	}
}

func TestParseInterspersedUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	_, err := parseInterspersed(fs, []string{"https://a", "--bogus"})

	if err == nil {
		t.Error("parseInterspersed accepted an unknown flag after a positional argument")
	}
}
