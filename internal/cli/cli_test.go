package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no command prints usage and exits 2", args: nil, wantCode: ExitError, wantStderr: "Usage:"},
		{name: "unknown command exits 2", args: []string{"bogus"}, wantCode: ExitError, wantStderr: `unknown command "bogus"`},
		{name: "version prints version", args: []string{"version"}, wantCode: ExitOK, wantStdout: "mcpwarden dev"},
		{name: "help prints usage to stdout", args: []string{"--help"}, wantCode: ExitOK, wantStdout: "Commands:"},
		{name: "scan without targets is a usage error", args: []string{"scan"}, wantCode: ExitError, wantStderr: "nothing to scan"},
		{name: "scan usage error points to help", args: []string{"scan", "--format", "xml", "https://a"}, wantCode: ExitError, wantStderr: `Run "mcpwarden scan -h"`},
		{name: "scan help prints flags to stdout", args: []string{"scan", "-h"}, wantCode: ExitOK, wantStdout: "-fail-on severity"},
		{name: "scan with valid flags is not implemented yet", args: []string{"scan", "https://a"}, wantCode: ExitError, wantStderr: "not implemented yet (1 targets parsed)"},
		{name: "list-checks is not implemented yet", args: []string{"list-checks"}, wantCode: ExitError, wantStderr: "not implemented"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := Run(tt.args, &stdout, &stderr, "dev")

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
