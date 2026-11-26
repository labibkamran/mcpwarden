# mcpwarden
Fast, offline security scanner for MCP servers — checks 2026-07-28 auth conformance and dangerous STDIO configs. Written in Go.

> Scan only servers you own or are authorized to test.

## Status

Early development (milestone 1: foundation). `mcpwarden version` works; `scan` and `list-checks` are not implemented yet.

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
