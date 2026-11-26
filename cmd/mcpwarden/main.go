// Command mcpwarden scans MCP servers and MCP client configs for
// authentication, authorization and configuration weaknesses.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Exit codes from SRS section 5.1 (FR-021).
const (
	exitOK    = 0
	exitError = 2
)

const usage = `Usage: mcpwarden <command> [flags]

Commands:
  scan         Scan MCP servers and client configs
  list-checks  List the security checks
  version      Print the version`

// version is set at build time with -ldflags "-X main.version=v1.2.3".
// It is a package-level var only because the linker can set nothing else.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI with args (without the program name) and returns the
// process exit code. It writes results to stdout and diagnostics to stderr.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return exitError
	}

	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "mcpwarden %s\n", buildVersion())
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprintln(stdout, usage)
		return exitOK
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "list-checks":
		fmt.Fprintf(stderr, "mcpwarden: %s is not implemented yet\n", args[0])
		return exitError
	default:
		fmt.Fprintf(stderr, "mcpwarden: unknown command %q\n\n%s\n", args[0], usage)
		return exitError
	}
}

// buildVersion returns the linker-set version, or the module version when the
// binary was built with "go install module@version".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
