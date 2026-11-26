package main

import (
	"errors"
	"flag"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
)

func TestParseScanArgsDefaults(t *testing.T) {
	opts, err := parseScanArgs([]string{"https://mcp.example.com/mcp"})

	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if len(opts.targets) != 1 || opts.targets[0].String() != "https://mcp.example.com/mcp" {
		t.Errorf("targets = %v, want [https://mcp.example.com/mcp]", opts.targets)
	}
	if opts.format != "text" {
		t.Errorf("format = %q, want text", opts.format)
	}
	if opts.failOn != check.SeverityHigh {
		t.Errorf("failOn = %v, want high", opts.failOn)
	}
	if opts.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", opts.timeout)
	}
	if opts.concurrency != 16 {
		t.Errorf("concurrency = %d, want 16", opts.concurrency)
	}
	if opts.output != "" || opts.configPath != "" || len(opts.headers) != 0 {
		t.Errorf("output, config and headers should be empty, got %q, %q, %v", opts.output, opts.configPath, opts.headers)
	}
}

func TestParseScanArgsAllFlags(t *testing.T) {
	args := []string{
		"https://a.example.com/mcp",
		"--config", "claude_desktop_config.json",
		"--format", "sarif",
		"--output", "report.sarif",
		"--fail-on", "critical",
		"--timeout", "3s",
		"--concurrency", "4",
		"--header", "Authorization: Bearer abc",
		"--enable", "MW011",
		"--disable", "MW003",
		"http://localhost:8080/mcp",
	}

	opts, err := parseScanArgs(args)

	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	want := scanOptions{
		targets:     opts.targets, // checked separately below
		configPath:  "claude_desktop_config.json",
		format:      "sarif",
		output:      "report.sarif",
		failOn:      check.SeverityCritical,
		timeout:     3 * time.Second,
		concurrency: 4,
		headers:     http.Header{"Authorization": {"Bearer abc"}},
		rules:       ruleSelection{enable: []string{"MW011"}, disable: []string{"MW003"}},
	}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("parseScanArgs =\n%+v\nwant\n%+v", opts, want)
	}
	if len(opts.targets) != 2 || opts.targets[1].String() != "http://localhost:8080/mcp" {
		t.Errorf("targets = %v, want both URLs in order", opts.targets)
	}
}

func TestParseScanArgsConfigOnly(t *testing.T) {
	opts, err := parseScanArgs([]string{"--config", "mcp.json"})

	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if opts.configPath != "mcp.json" || len(opts.targets) != 0 {
		t.Errorf("configPath = %q, targets = %v; want mcp.json and no URL targets", opts.configPath, opts.targets)
	}
}

func TestParseScanArgsDeduplicatesTargets(t *testing.T) {
	opts, err := parseScanArgs([]string{"https://A.example.com:443/mcp", "https://a.example.com/mcp#x"})

	if err != nil {
		t.Fatalf("parseScanArgs error: %v", err)
	}
	if len(opts.targets) != 1 {
		t.Errorf("targets = %v, want one normalized target", opts.targets)
	}
}

func TestParseScanArgsHelp(t *testing.T) {
	_, err := parseScanArgs([]string{"--help"})

	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("parseScanArgs(--help) error = %v, want flag.ErrHelp", err)
	}
}

func TestParseScanArgsRejects(t *testing.T) {
	const url = "https://mcp.example.com/mcp"
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "nothing to scan", args: nil, wantErr: "nothing to scan"},
		{name: "bad scheme", args: []string{"ftp://x"}, wantErr: `target #1: unsupported scheme "ftp"`},
		{name: "bad format", args: []string{url, "--format", "xml"}, wantErr: `--format "xml"`},
		{name: "bad fail-on", args: []string{url, "--fail-on", "severe"}, wantErr: "--fail-on"},
		{name: "zero timeout", args: []string{url, "--timeout", "0s"}, wantErr: "--timeout 0s"},
		{name: "unparsable timeout", args: []string{url, "--timeout", "soon"}, wantErr: "-timeout"},
		{name: "zero concurrency", args: []string{url, "--concurrency", "0"}, wantErr: "--concurrency 0"},
		{name: "bad header", args: []string{url, "--header", "nocolon"}, wantErr: "--header #1"},
		{name: "bad rule id", args: []string{url, "--disable", "X1"}, wantErr: `--disable "X1"`},
		{name: "unknown flag", args: []string{url, "--bogus"}, wantErr: "-bogus"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseScanArgs(tt.args)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseScanArgs(%q) error = %v, want it to contain %q", tt.args, err, tt.wantErr)
			}
		})
	}
}
