// Command mcpwarden scans MCP servers and MCP client configs for
// authentication, authorization and configuration weaknesses.
package main

import (
	"os"
	"runtime/debug"

	"github.com/labibkamran/mcpwarden/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
// It is a package-level var only because the linker can set nothing else.
var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, buildVersion()))
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
