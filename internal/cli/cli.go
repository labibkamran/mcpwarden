// Package cli implements the mcpwarden command line (IF-001): it parses
// arguments, runs the requested command and returns the exit code.
package cli

import (
	"fmt"
	"io"
)

// Exit codes from SRS section 5.1 (FR-021).
const (
	ExitOK    = 0
	ExitError = 2
)

const usage = `Usage: mcpwarden <command> [flags]

Commands:
  scan         Scan MCP servers and client configs
  list-checks  List the security checks
  version      Print the version`

// Run executes the CLI with args (without the program name) and returns the
// process exit code. It writes results to stdout and diagnostics to stderr;
// version is what the version command prints.
func Run(args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return ExitError
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "mcpwarden %s\n", version)
		return ExitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprintln(stdout, usage)
		return ExitOK
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "list-checks":
		fmt.Fprintf(stderr, "mcpwarden: %s is not implemented yet\n", args[0])
		return ExitError
	default:
		fmt.Fprintf(stderr, "mcpwarden: unknown command %q\n\n%s\n", args[0], usage)
		return ExitError
	}
}
