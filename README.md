# mcpwarden
Fast, offline security scanner for MCP servers — checks 2026-07-28 auth conformance and dangerous STDIO configs. Written in Go.

> Scan only servers you own or are authorized to test.

## Status

Early development (milestone 1: foundation). `scan` parses and validates all of its flags and targets, but scanning itself lands in milestone 2, so a valid scan exits 2 for now. `list-checks` arrives with the first rules.

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

Flags and URLs can come in any order; `--header`, `--enable` and `--disable` can repeat. Only `http` and `https` URLs are accepted, and URLs with embedded credentials are rejected: pass credentials with `--header`, whose values never appear in output.

| Exit code | Meaning |
|---|---|
| 0 | Scan finished; no finding at or above `--fail-on` |
| 1 | Scan finished; at least one finding at or above `--fail-on` |
| 2 | Usage error or scanner failure; no reliable result |

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

Project layout follows the [official Go module layout](https://go.dev/doc/modules/layout): commands in `cmd/`, logic in `internal/`. See [AGENTS.md](AGENTS.md) for the package map and coding guidelines.

## License

Apache-2.0
