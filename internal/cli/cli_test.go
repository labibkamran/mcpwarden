package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/cli"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no command prints usage and exits 2", args: nil, wantCode: cli.ExitError, wantStderr: "Usage:"},
		{name: "unknown command exits 2", args: []string{"bogus"}, wantCode: cli.ExitError, wantStderr: `unknown command "bogus"`},
		{name: "version prints the given version", args: []string{"version"}, wantCode: cli.ExitOK, wantStdout: "mcpwarden v9.9.9"},
		{name: "help prints usage to stdout", args: []string{"--help"}, wantCode: cli.ExitOK, wantStdout: "Commands:"},
		{name: "scan without targets is a usage error", args: []string{"scan"}, wantCode: cli.ExitError, wantStderr: "nothing to scan"},
		{name: "scan usage error points to help", args: []string{"scan", "--format", "xml", "https://a"}, wantCode: cli.ExitError, wantStderr: `Run "mcpwarden scan -h"`},
		{name: "scan help prints flags to stdout", args: []string{"scan", "-h"}, wantCode: cli.ExitOK, wantStdout: "-fail-on severity"},
		{name: "list-checks prints the catalog", args: []string{"list-checks"}, wantCode: cli.ExitOK, wantStdout: "MW001  critical  No authentication required"},
		{name: "list-checks marks opt-in rules", args: []string{"list-checks"}, wantCode: cli.ExitOK, wantStdout: "Token audience not bound (opt-in: --enable MW011)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := cli.Run(tt.args, &stdout, &stderr, "v9.9.9")

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestRunNeverPrintsHeaderValues(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "missing colon", header: "Bearer s3cret"},
		{name: "invalid name", header: "X Auth: s3cret"},
		{name: "line break in value", header: "X-A: s3cret\r\nHost: evil"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := cli.Run([]string{"scan", "https://a", "--header", tt.header}, &stdout, &stderr, "dev")

			if code != cli.ExitError {
				t.Errorf("exit code = %d, want %d", code, cli.ExitError)
			}
			if strings.Contains(stdout.String()+stderr.String(), "s3cret") {
				t.Errorf("output leaks the header value: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
