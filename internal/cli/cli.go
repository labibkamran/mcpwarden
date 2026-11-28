// Package cli implements the mcpwarden command line (IF-001): it dispatches
// commands, prints usage and returns the process exit code (SRS 5.1, FR-021).
// Results go to stdout, diagnostics to stderr.
package cli

import (
	"fmt"
	"io"
)

const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

const usage = `Usage: mcpwarden <command> [flags]

Commands:
  scan         Scan MCP servers and client configs
  list-checks  List the security checks
  version      Print the version`

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
		return runScan(args[1:], stdout, stderr, version)
	case "list-checks":
		fmt.Fprintf(stderr, "mcpwarden: %s is not implemented yet\n", args[0])
		return ExitError
	default:
		fmt.Fprintf(stderr, "mcpwarden: unknown command %q\n\n%s\n", args[0], usage)
		return ExitError
	}
}
