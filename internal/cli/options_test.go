package cli_test

import (
	"errors"
	"flag"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/cli"
)

func TestParseScanArgsDefaults(t *testing.T) {
	opts, err := cli.ParseScanArgs([]string{"https://mcp.example.com/mcp"})

	if err != nil {
		t.Fatalf("ParseScanArgs error: %v", err)
	}
	if len(opts.Targets) != 1 || opts.Targets[0].String() != "https://mcp.example.com/mcp" {
		t.Errorf("Targets = %v, want [https://mcp.example.com/mcp]", opts.Targets)
	}
	if opts.Format != "text" {
		t.Errorf("Format = %q, want text", opts.Format)
	}
	if opts.FailOn != check.SeverityHigh {
		t.Errorf("FailOn = %v, want high", opts.FailOn)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", opts.Timeout)
	}
	if opts.Concurrency != 16 {
		t.Errorf("Concurrency = %d, want 16", opts.Concurrency)
	}
	if opts.Output != "" || opts.ConfigPath != "" || len(opts.Headers) != 0 {
		t.Errorf("Output, ConfigPath and Headers should be empty, got %q, %q, %v", opts.Output, opts.ConfigPath, opts.Headers)
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
		"--enable", "MW002",
		"--disable", "MW003",
		"http://localhost:8080/mcp",
	}

	opts, err := cli.ParseScanArgs(args)

	if err != nil {
		t.Fatalf("ParseScanArgs error: %v", err)
	}
	want := cli.ScanOptions{
		Targets:     opts.Targets,
		ConfigPath:  "claude_desktop_config.json",
		Format:      "sarif",
		Output:      "report.sarif",
		FailOn:      check.SeverityCritical,
		Timeout:     3 * time.Second,
		Concurrency: 4,
		Headers:     http.Header{"Authorization": {"Bearer abc"}},
		Rules:       check.RuleSelection{Enable: []string{"MW002"}, Disable: []string{"MW003"}},
	}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("ParseScanArgs =\n%+v\nwant\n%+v", opts, want)
	}
	if len(opts.Targets) != 2 || opts.Targets[1].String() != "http://localhost:8080/mcp" {
		t.Errorf("Targets = %v, want both URLs in order", opts.Targets)
	}
}

func TestParseScanArgsConfigOnly(t *testing.T) {
	opts, err := cli.ParseScanArgs([]string{"--config", "mcp.json"})

	if err != nil {
		t.Fatalf("ParseScanArgs error: %v", err)
	}
	if opts.ConfigPath != "mcp.json" || len(opts.Targets) != 0 {
		t.Errorf("ConfigPath = %q, Targets = %v; want mcp.json and no URL targets", opts.ConfigPath, opts.Targets)
	}
}

func TestParseScanArgsDeduplicatesTargets(t *testing.T) {
	opts, err := cli.ParseScanArgs([]string{"https://A.example.com:443/mcp", "https://a.example.com/mcp#x"})

	if err != nil {
		t.Fatalf("ParseScanArgs error: %v", err)
	}
	if len(opts.Targets) != 1 {
		t.Errorf("Targets = %v, want one normalized target", opts.Targets)
	}
}

func TestParseScanArgsHelp(t *testing.T) {
	_, err := cli.ParseScanArgs([]string{"--help"})

	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("ParseScanArgs(--help) error = %v, want flag.ErrHelp", err)
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
		{name: "bad rule id", args: []string{url, "--disable", "X1"}, wantErr: `unknown rule ID "X1"`},
		{name: "unknown flag", args: []string{url, "--bogus"}, wantErr: "-bogus"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cli.ParseScanArgs(tt.args)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseScanArgs(%q) error = %v, want it to contain %q", tt.args, err, tt.wantErr)
			}
		})
	}
}
