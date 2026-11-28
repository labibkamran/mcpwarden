package cli_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/cli"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

const tokenHeader = "Authorization: Bearer " + mockserver.Token

func serve(t *testing.T, cfg mockserver.Config) string {
	t.Helper()
	srv := mockserver.New(cfg)
	t.Cleanup(srv.Close)
	return srv.URL + mockserver.Path
}

func unreachableURL() string {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	return srv.URL
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = cli.Run(args, &out, &errOut, "test")
	return code, out.String(), errOut.String()
}

func TestScanExitCodes(t *testing.T) {
	open := mockserver.Secure()
	open.RequireAuth = false
	wildcard := mockserver.Secure()
	wildcard.AllowOrigin = "*"
	secureURL, openURL, wildcardURL := serve(t, mockserver.Secure()), serve(t, open), serve(t, wildcard)
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
	}{
		{name: "secure server passes", args: []string{secureURL}, wantCode: cli.ExitOK, wantStdout: "Grade A"},
		{name: "open server fails on MW001", args: []string{openURL}, wantCode: cli.ExitFindings, wantStdout: "CRITICAL  MW001"},
		{name: "disabled rule is not run", args: []string{openURL, "--disable", "MW001"}, wantCode: cli.ExitOK, wantStdout: "Grade A"},
		{name: "medium finding passes fail-on high", args: []string{wildcardURL}, wantCode: cli.ExitOK, wantStdout: "MEDIUM    MW003"},
		{name: "medium finding fails fail-on medium", args: []string{wildcardURL, "--fail-on", "medium"}, wantCode: cli.ExitFindings, wantStdout: "MW003"},
		{name: "unreachable target exits 2", args: []string{unreachableURL()}, wantCode: cli.ExitError, wantStdout: "Unreachable"},
		{name: "findings outrank an unreachable target", args: []string{openURL, unreachableURL()}, wantCode: cli.ExitFindings, wantStdout: "1 unreachable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(append([]string{"scan"}, tt.args...)...)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tt.wantCode, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tt.wantStdout)
			}
		})
	}
}

func TestScanDoesNotGradeANonMCPURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<pre>Cannot POST /</pre>"))
	}))
	defer srv.Close()

	code, stdout, _ := runCLI("scan", srv.URL)

	if code != cli.ExitError || !strings.Contains(stdout, "Not an MCP endpoint") || strings.Contains(stdout, "Grade") {
		t.Errorf("exit %d, stdout %q; want 2, \"Not an MCP endpoint\" and no grade", code, stdout)
	}
}

func TestScanNeverPrintsTheToken(t *testing.T) {
	trusting := mockserver.Secure()
	trusting.ValidateOrigin = false

	code, stdout, stderr := runCLI("scan", serve(t, trusting), "--header", tokenHeader)

	if code != cli.ExitFindings || !strings.Contains(stdout, "MW002") {
		t.Fatalf("exit code %d, stdout %q; want 1 and an MW002 finding", code, stdout)
	}
	if strings.Contains(stdout+stderr, mockserver.Token) {
		t.Error("the token passed with --header appears in the output")
	}
}

func TestScanWritesReportFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.txt")

	code, stdout, _ := runCLI("scan", serve(t, mockserver.Secure()), "--output", path)

	report, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	info, _ := os.Stat(path)
	if code != cli.ExitOK || stdout != "" || !strings.Contains(string(report), "Grade A") {
		t.Errorf("exit %d, stdout %q, report %q; want 0, nothing on stdout, the report in the file", code, stdout, report)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("report file mode = %o, want 600", perm)
	}
}

func TestScanReportFileError(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing", "report.txt")

	code, _, stderr := runCLI("scan", serve(t, mockserver.Secure()), "--output", missingDir)

	if code != cli.ExitError || !strings.Contains(stderr, "write report") {
		t.Errorf("exit %d, stderr %q; want 2 and a write report error", code, stderr)
	}
}

func TestScanRefusesUnfinishedFeatures(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{name: "config files", args: []string{"scan", "--config", "mcp.json"}, wantStderr: "arrives in milestone 3"},
		{name: "json report", args: []string{"scan", "https://a.example", "--format", "json"}, wantStderr: "arrive in milestone 4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(tt.args...)

			if code != cli.ExitError || !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("exit %d, stderr %q; want 2 and %q", code, stderr, tt.wantStderr)
			}
		})
	}
}
