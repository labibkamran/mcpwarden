# mcpwarden
Fast, offline security scanner for MCP servers — checks 2026-07-28 auth conformance and dangerous STDIO configs. Written in Go.

> Scan only servers you own or are authorized to test.

## Status

Milestone 3 of 5: `scan` checks remote MCP servers and MCP client config files (Claude Desktop, Cursor, Claude Code, VS Code) against rules [MW001–MW012](docs/rules.md) and prints a text report with a grade from A to F. JSON and SARIF reports arrive in milestone 4.

## Example

```text
$ mcpwarden scan https://mcp.example.com/mcp
https://mcp.example.com/mcp
  Grade D · 1 finding

  CRITICAL  MW001  No authentication required
            tools/list returned 200 with 7 tools and no token
            Fix:  Require OAuth 2.1 bearer tokens on every request and answer 401 without one.
            Docs: https://github.com/labibkamran/mcpwarden/blob/main/docs/rules.md#mw001

1 target: 1 scanned, 0 unreachable · 1 finding (1 critical)
```

Scan the servers in a client config the same way. Commands in it are read as text and never run; remote entries are probed like URL arguments:

```sh
mcpwarden scan --config ~/Library/Application\ Support/Claude/claude_desktop_config.json
mcpwarden scan --config .vscode/mcp.json https://mcp.example.com/mcp
```

`mcpwarden list-checks` prints every rule; [docs/rules.md](docs/rules.md) explains each one and how to fix it. MW011 and MW012 need a token in `--header` and are opt-in: turn them on with `--enable`.

## What mcpwarden sends

Only read-only requests, at most ten per server plus same-host redirects, each with a 10 s timeout and a 1 MB limit on the answer:

- `POST tools/list` without credentials, then again from `Origin: https://evil.example`, carrying any `--header` values
- with `--header` values, `POST tools/list` once more as your client, so scope and audience rules can see what the token unlocks
- an `OPTIONS` CORS preflight from that origin
- `GET` requests for OAuth metadata (RFC 9728, RFC 8414, OpenID Connect) on the server and its authorization server

Redirects are followed only on the same host, at most three times. Requests identify themselves as `mcpwarden/<version>` with a link to this project.

## Usage

```sh
mcpwarden scan [URL...] [--config PATH]
               [--format text|json|sarif] [--output FILE]
               [--fail-on low|medium|high|critical]   # default high
               [--timeout 10s] [--concurrency 16]
               [--header "Authorization: Bearer $TOKEN"]
               [--enable MW011] [--disable MW003]
mcpwarden list-checks
mcpwarden version
```

Flags and URLs can come in any order; `--header`, `--enable` and `--disable` can repeat. `--config` reads `mcpServers` (Claude Desktop, Cursor, Claude Code) or `servers` (VS Code, comments allowed) from a file up to 1 MB. Only `http` and `https` URLs are accepted, and URLs with embedded credentials are rejected: pass credentials with `--header`, whose values never appear in output.

| Exit code | Meaning |
|---|---|
| 0 | Scan finished; no finding at or above `--fail-on` |
| 1 | Scan finished; at least one finding at or above `--fail-on` |
| 2 | Usage error or scanner failure, including an unreachable target or a URL that is not an MCP endpoint; no reliable result |

Exit code 1 wins when one target has findings and another is unreachable.

## Build

Requires Go 1.27 or later (with the default `GOTOOLCHAIN=auto`, older Go downloads it automatically).

```sh
go install github.com/labibkamran/mcpwarden/cmd/mcpwarden@latest
# or from a clone
make build   # writes bin/mcpwarden
```

## Development

Tools: Go, [golangci-lint v2](https://golangci-lint.run/docs/welcome/install/), make.

```sh
make check   # vet, lint, test (-race), govulncheck, build — same as CI
make test
make fmt
```

Project layout follows the [official Go module layout](https://go.dev/doc/modules/layout): commands in `cmd/`, logic in `internal/` with one package per feature, and integration tests with mock MCP servers in `test/`. See [AGENTS.md](AGENTS.md) for the package map and coding guidelines.

## License

Apache-2.0
