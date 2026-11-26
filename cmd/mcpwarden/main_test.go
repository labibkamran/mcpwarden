package main

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
		{name: "no command prints usage and exits 2", args: nil, wantCode: exitError, wantStderr: "Usage:"},
		{name: "unknown command exits 2", args: []string{"bogus"}, wantCode: exitError, wantStderr: `unknown command "bogus"`},
		{name: "version prints version", args: []string{"version"}, wantCode: exitOK, wantStdout: "mcpwarden dev"},
		{name: "help prints usage to stdout", args: []string{"--help"}, wantCode: exitOK, wantStdout: "Commands:"},
		{name: "scan is not implemented yet", args: []string{"scan"}, wantCode: exitError, wantStderr: "not implemented"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(tt.args, &stdout, &stderr)

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
