// Command mcpwarden scans MCP servers and MCP client configs for authentication,
// authorization and configuration weaknesses. main only resolves the build version
// and hands over to internal/cli. version is a package-level var because
// -ldflags "-X main.version=v1.2.3" can set nothing else; binaries built with
// "go install module@version" fall back to the module version.
package main

import (
	"os"
	"runtime/debug"

	"github.com/labibkamran/mcpwarden/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, buildVersion()))
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
