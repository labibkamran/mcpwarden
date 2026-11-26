# AGENTS.md

Instructions for any coding agent (Claude Code, Codex, Cursor, Copilot) or engineer working in this repository.
Part 1 is project context. Part 2 is the general coding guidelines.

---

# Part 1: Project context

## What this is

mcpwarden is an offline-first security scanner, written in Go, that tests MCP servers and MCP client configs for
authentication, authorization and configuration weaknesses. Release 1.0 is a CLI; release 2.0 adds a multi-tenant
scan service on the same engine. The SRS (`mcpwarden — Software Requirements Specification`, Nov 25 2026) is the
single reference for requirements (FR-xxx, NFR-xxx) and rules (MW001–MW012). Cite requirement IDs in code comments,
tests and commit bodies where it helps.

## Non-negotiable constraints (from the SRS)

- Every probe is read-only: only GET, OPTIONS, and POST of read-only MCP methods (FR-011). Never send a request that
  could create, change or delete data on a target.
- STDIO commands found in config files are parsed as text and **never executed**.
- No LLM calls, API keys or network access beyond the targets themselves (NFR-009).
- Header values, tokens and secrets are redacted in every report and log line (FR-022, NFR-010).
- Only `internal/probe` touches the network. Checks are pure: evidence in, findings out, no I/O (FR-015).
- Adding a rule = one new file plus its test, with no engine change (NFR-014).
- Bounded everything: 1 MB response cap, 10 s request timeout, same-host redirects (max 3) (FR-012).
- Exit codes: 0 passed, 1 findings at or above `--fail-on`, 2 usage or scanner error (FR-021).
- Standard library first; the official MCP Go SDK for protocol work. Ask before adding any other dependency.

## Layout

Follows the official Go module layout (https://go.dev/doc/modules/layout): commands in `cmd/`, all logic in
`internal/`, **one folder per feature**. Create a package only when the first code for it lands; do not add empty
placeholder packages.

```
cmd/mcpwarden/main.go     entry point only: build version + cli.Run
internal/<feature>/       one package per feature (table below)
  <name>.go               code
  <name>_test.go          its tests, package <feature>_test
test/                     added in M2: integration tests, mock MCP servers, golden files
```

| Package | Responsibility |
|---|---|
| `cmd/mcpwarden` | Entry point only: compute the build version and call `cli.Run` |
| `internal/cli` | Commands, flag parsing and validation, exit codes (IF-001) |
| `internal/target` | Turn URLs and config files into `Target` values |
| `internal/engine` | Worker pool, deadlines, rate limits, per-target pipeline |
| `internal/probe` | HTTP prober, OAuth fetcher, MCP client; builds `Evidence` |
| `internal/check` | Registry of rules MW001–MW012; evidence in, findings out |
| `internal/score` | Severity, OWASP labels, grade, fail-on decision |
| `internal/report` | Text, JSON and SARIF writers |
| `cmd/mcpwarden-api`, `cmd/mcpwarden-worker` | v2 service only; do not start before v1.0 ships |

## Tests

- **Unit tests** sit beside the code they test (`target.go` → `target_test.go`), as `go test`, coverage and GoLand
  expect, but in the external test package (`package target_test`). They use only the exported API, so internal
  refactors never break them. Name each test file after the source file it covers.
- Use an internal test (`package target`) only when behavior cannot be reached through the public API, and say why
  in a comment.
- **Fuzz tests** for parsers live beside the parser (`fuzz_test.go`) and are added to `.github/workflows/fuzz.yml`.
- **Integration tests, mock MCP servers and golden files** go in the top-level `test/` folder (from M2). Every rule
  ships with a vulnerable and a secure `httptest` server there.
- Fixed input files for a package go in `<package>/testdata/`, which the Go tool ignores when building.
- `internal/check` and `internal/probe` must keep at least 80% test coverage (NFR-014).

## Commands

```sh
make test     # go test -race ./...
make lint     # golangci-lint run (config: .golangci.yml)
make fmt      # golangci-lint fmt (gofmt + goimports)
make vet      # go vet ./...
make vuln     # govulncheck ./...
make build    # static binary in bin/mcpwarden
make cover    # coverage summary
make check    # everything CI runs, in order
```

Run `make check` before saying a change is done.

---

# Part 2: Coding guidelines

They combine widely used senior-engineering practice: Google's engineering and Go style guides, the Uber Go guide,
*Refactoring* (Fowler), *A Philosophy of Software Design* (Ousterhout), *Code Complete* (McConnell), SonarQube
defaults, Google's testing guidance, and OWASP secure coding.

**How to apply them**
- The repository's own conventions, linters and existing patterns override this file. Match the code around you.
- Numbers below are review triggers, not laws. Break a rule when following it makes the code worse, and say why.
- When rules conflict, prioritize: correctness and security > readability > consistency with the codebase > simplicity > performance > brevity.

---

## 0. Core rules (short version)

1. Read the surrounding code before writing. Match its structure, naming and style.
2. Make the smallest change that fully solves the task. No speculative features, flags or abstractions.
3. One function = one job at one level of abstraction. If its name needs "and", split it.
4. Keep the happy path unindented: guard clauses and early returns, max 3 levels of nesting.
5. Extract a function when it names an idea, not to hit a line count. Avoid one-line wrappers that add nothing.
6. Prefer duplication over the wrong abstraction. Abstract on the third repetition with the same reason to change.
7. Names reveal intent. Comments explain *why*, never restate *what*.
8. Validate input at boundaries. Handle each error once, with context. Never swallow errors.
9. Every behavior change ships with tests that check behavior through the public API.
10. No secrets in code, logs or errors. Treat all external input as untrusted.
11. Run formatter, linter and tests before saying "done". Report anything you could not verify.
12. Keep changes small and focused. Never mix refactoring with behavior changes.

---

## 1. Workflow

- Before coding: read the relevant files, find how similar problems are already solved, and reuse that.
- Search for an existing helper before writing a new one.
- For multi-file or risky changes, state the plan first (files touched, approach, risks).
- Ask before decisions that are hard to reverse: public API changes, schema/migrations, deleting data, new dependencies.
- Do not invent APIs, flags, config keys or file paths. Verify them in the code or official docs.
- Do not add a dependency without asking. Prefer the standard library and dependencies already in use.
- Do not silence checks to get green builds (`//nolint`, `@ts-ignore`, `any`, skipped tests) without a written reason.
- Never weaken or delete a failing test to make it pass. Fix the code, or explain why the test is wrong.
- Stay in scope. List unrelated problems you notice as follow-ups instead of fixing them silently.
- Finish with: what changed, why, how it was verified, and what remains or is risky.

## 2. Simplicity and scope

- YAGNI: solve the problem that exists now. Over-engineering (more generic than needed, unused functionality) is a defect.
- KISS: the simplest design that meets the requirements wins. Clever code is a cost.
- No speculative generality: no interface with one implementation, no config option nobody asked for, no plugin system "for later".
- Delete dead code. Do not leave commented-out code; version control remembers it.
- Prefer boring, well-known solutions over novel ones.

## 3. Functions

**Responsibility**
- One function does one thing at one level of abstraction. Do not mix high-level steps with low-level details.
- The name states what it does. If a good name is hard to find, the function probably does too much.
- Separate commands (change state) from queries (return data). No hidden side effects in getters.
- Prefer pure functions for logic; push I/O (network, disk, DB, clock) to the edges.

**Size (signals, not laws)**
- Target: fits on one screen, roughly 40 lines of logic or fewer.
- Over ~60 lines: look for a responsibility to extract. Over ~100 lines: needs a clear reason (e.g. a flat `switch`, a table, generated code).
- Length alone is not the problem; mixed responsibilities and hidden intent are. Do not split sequential logic into fragments that force the reader to jump around.

**When to extract a function**
- A block needs a comment to explain *what* it does: extract it and use the comment as the name.
- The same logic appears a third time with the same reason to change.
- A block sits at a different level of abstraction than the rest of the function.
- Nesting goes deeper than 3 levels.

**When not to extract**
- One-line wrappers that only rename a call.
- Helpers that cannot be understood without the caller's local state.
- Splitting only to satisfy a line limit.

**Complexity**
- Cognitive complexity ≤ 15 per function (SonarQube default). Cyclomatic complexity ideally ≤ 10; above 20 is too complex.
- Max nesting depth 3. Use guard clauses, early `return`/`continue`, and extracted predicates.
- Avoid `else` after a `return`.
- Replace magic numbers and strings with named constants.

**Parameters**
- Prefer ≤ 4 parameters. With 5 or more, group related ones into a struct/options object.
- No boolean flag parameters that switch behavior (`render(true)`). Write two functions or use a named option.
- Do not mutate inputs unless that is the function's documented purpose.

## 4. Modules, files and components

- Deep modules: a small, simple interface hiding a substantial implementation. Avoid shallow classes that just pass calls through.
- High cohesion, low coupling: things that change together live together.
- Organize by feature or domain, not by technical type, once a project grows.
- Dependency direction: core/business logic must not import infrastructure (DB, HTTP, frameworks). Depend on small interfaces at boundaries.
- Keep the public surface minimal. Unexported/private by default; export only what callers need.
- No `utils`, `common`, `helpers` or `misc` dumping grounds. Name packages and modules after what they provide.
- Composition over inheritance. Keep inheritance hierarchies shallow.
- Files over ~400 lines: check for mixed responsibilities. Split by responsibility, not alphabetically.
- One clear entry point per module. Avoid circular dependencies.
- UI components: one responsibility each; separate data fetching/state from presentation; keep props small and typed; lift state only as high as needed.

## 5. Reuse and abstraction

- DRY means one source of truth for each piece of *knowledge* (a rule, a format, a constant), not merging code that only looks similar.
- Rule of three: duplicate once if needed; abstract when the third copy appears and all copies change for the same reason.
- AHA (avoid hasty abstractions): duplication is cheap to fix; a wrong abstraction is expensive.
- Warning signs of a wrong abstraction: growing parameter lists, mode flags, `if caller == X` branches.
- To fix a wrong abstraction: inline it back into callers, delete what each caller does not need, then re-extract.
- Reusable code takes general inputs and has no caller-specific branches. Design it for the cases that exist, not imagined ones.

## 6. Naming

- Names reveal intent: `elapsedDays`, not `d`; `retryBackoff`, not `val2`.
- Name length grows with scope: short in a 3-line loop, descriptive for package-level identifiers.
- One word per concept across the codebase (do not mix `fetch`, `get` and `retrieve` for the same idea).
- Functions are verbs (`parseConfig`), types are nouns (`ScanReport`), booleans are predicates (`isValid`, `hasAuth`).
- Avoid vague names: `data`, `info`, `manager`, `handler`, `process`, `temp` — unless the meaning is precise in context.
- No type encodings in names (`strName`, `userList` when it is a map). No unclear abbreviations.

## 7. Errors and failure handling

- Fail fast: validate preconditions at function and system boundaries; reject invalid input early.
- Handle each error once: either handle it (recover, retry, degrade), or return it with added context. Do not log and also return.
- Add context when propagating ("open config %s: %w"), and preserve the original cause.
- Never swallow errors: no empty `catch`, no ignored error returns, no `except: pass`.
- Do not use exceptions/errors for normal control flow. Do not signal errors with in-band values like `-1` or `""`.
- Error messages are actionable and contain no secrets, tokens or personal data.
- Always release resources (`defer`, `finally`, `with`, `using`), including on error paths.
- Set timeouts on every network call and external process. Retries use backoff with jitter and only for idempotent operations.

## 8. Data and state

- Prefer immutable data. Keep variable scope as small as possible.
- No mutable global state. Pass dependencies explicitly (constructor/function parameters).
- Make invalid states unrepresentable: enums/typed constants instead of free strings, required fields set in constructors.
- Parse, don't just validate: convert raw input into typed values once at the boundary, then trust the types inside.
- Explicit over implicit: no hidden configuration, no action-at-a-distance.

## 9. Comments and documentation

- **House style: comments go only at the start of a file.** No comments between lines, no trailing comments, no
  doc comments on functions, types or fields. Lint is configured to allow undocumented exported identifiers.
- The file header says what the file is for and anything a reader cannot see from the code: constraints,
  trade-offs, defaults with their source, workarounds, and the SRS requirement, RFC or issue behind them.
- In the package's main file the header sits directly above `package` (it becomes the package doc). In other
  files, leave a blank line between the header and `package` so it is not merged into the package doc.
- Write only necessary comments. Code shows *what* and *how*: when a line needs explaining, rename or extract
  until it does not (e.g. `if isIPv6 := strings.Contains(host, ":"); isIPv6`).
- Keep headers in sync with the code. Delete stale ones.
- Config files (YAML, Makefile) follow the same rule: one header comment at the top. Exception: the
  `# vX.Y.Z` comment after a pinned action SHA, which Dependabot reads.
- Update the README and docs in the same change when behavior, flags or setup change.

## 10. Testing

- Every behavior change includes tests. Every bug fix starts with a failing test that reproduces it.
- Test behavior through the public API, not implementation details. Avoid change-detector tests that break on harmless refactors.
- One behavior per test, with a descriptive name (`returns error when token is expired`).
- Structure: Arrange, Act, Assert. Prefer DAMP (descriptive) over DRY in tests; a reader should understand a test without jumping to helpers.
- No logic (loops, conditionals) in test bodies; use table-driven tests for variations.
- Deterministic tests: no real network, no sleeps, no dependence on wall-clock time or random order. Inject clocks and randomness.
- Prefer real objects or fakes over mocks. Do not mock types you do not own; wrap them behind your own interface.
- Test pyramid: many fast unit tests, fewer integration tests, few end-to-end tests.
- Cover edge cases: empty, nil/null, zero, max size, invalid input, timeouts, concurrent access.

## 11. Security

- Treat all external input as untrusted (users, files, network, environment, other services, LLM output). Validate on the trusted side.
- Validate with allowlists (expected type, length, format, range); reject on failure rather than "cleaning" input.
- Parameterized queries only. Never build SQL, shell commands or HTML by string concatenation.
- Encode output for its context (HTML, URL, shell, logs).
- No secrets in code, tests, logs, errors or commits. Load them from environment variables or a secrets manager.
- Least privilege for tokens, service accounts, file permissions and CI jobs. Secure defaults: deny unless allowed.
- Use vetted crypto libraries; never implement crypto yourself.
- Limit request/response sizes and set timeouts to prevent resource exhaustion.
- Pin dependency versions; review new dependencies for maintenance and known vulnerabilities.

## 12. Performance and concurrency

- Correct and clear first. Measure (profile/benchmark) before optimizing, then optimize the measured hot path.
- Avoid obvious waste: N+1 queries, unbounded loops or memory, loading whole datasets when streaming or paging works.
- Every concurrent task (goroutine/thread/async job) has a clear owner, a stop condition and cancellation (e.g. `context`).
- No fire-and-forget background work. Bound concurrency with worker pools or semaphores.
- Protect shared state (locks or message passing). Run the race detector/thread sanitizer where available.
- Make operations idempotent where retries are possible.

## 13. Logging and observability

- Structured logs (key-value) with levels. Include request/correlation IDs.
- Log at boundaries and decision points, not in every function.
- Never log secrets, tokens, passwords or personal data.
- Log messages are actionable: what happened, to what, and what to do.
- Expose metrics for things you would alert on (errors, latency, saturation).

## 14. Changes, commits and pull requests

- Small, focused changes: ideally under ~200 changed lines, one logical change per PR, including its tests.
- Separate refactoring, formatting and behavior changes into different commits.
- Commit message: imperative summary of ≤ 72 characters ("Add PKCE check to OAuth probe"), then a body explaining *why*.
- Do not commit generated files, build output, secrets or local config unless the repo expects it.
- Commits are authored by me (the repository owner). Do not add AI co-author lines or "Generated with" trailers unless I ask.

## 15. Language notes

**Go**
- `gofmt`/`goimports`, `go vet`, `golangci-lint` must pass. Run tests with `-race`.
- `error` is the last return value. Wrap with `fmt.Errorf("context: %w", err)`. Error strings are lowercase, without trailing punctuation.
- Handle errors first and return early; the normal path stays unindented.
- Accept interfaces, return concrete types. Define small interfaces where they are consumed.
- `context.Context` is the first parameter for anything that blocks or does I/O. Never store it in a struct.
- Avoid `init()`, mutable package-level variables and `panic` in library code.
- Package names: short, lowercase, no `util`/`common`. Table-driven tests with `t.Run`.

**Python**
- PEP 8, type hints on public functions, `ruff`/`black` formatting, `pytest`.
- Use context managers for resources; no mutable default arguments; no bare `except`.

**TypeScript/JavaScript**
- `strict` mode on; no `any` without a comment explaining why; ESLint + Prettier.
- Handle every promise rejection; no floating promises. Prefer `const` and immutable updates.

## 16. Thresholds at a glance

| Metric | Target | Review trigger | Hard stop / needs reason |
|---|---|---|---|
| Function length (logic lines) | ≤ 40 | > 60 | > 100 |
| Cognitive complexity per function | ≤ 10 | > 15 | > 25 |
| Cyclomatic complexity | ≤ 10 | > 15 | > 20 |
| Nesting depth | ≤ 2 | 3 | > 3 |
| Parameters | ≤ 4 | 5–6 | ≥ 7 |
| File length | ≤ 300 | > 400 | > 800 |
| PR / change size (changed lines) | ≤ 200 | > 400 | > 800 |
| Repetitions before abstracting | — | 3rd copy | — |

---

## References

- Google Engineering Practices (code review, small CLs): https://google.github.io/eng-practices/
- Google Go Style Guide: https://google.github.io/styleguide/go/ · Uber Go Style Guide: https://github.com/uber-go/guide
- Effective Go: https://go.dev/doc/effective_go · Go module layout: https://go.dev/doc/modules/layout
- Martin Fowler, "Function Length": https://martinfowler.com/bliki/FunctionLength.html
- Ousterhout vs Martin, APOSD vs Clean Code: https://github.com/johnousterhout/aposd-vs-clean-code
- Kent C. Dodds, AHA Programming: https://kentcdodds.com/blog/aha-programming
- Google Testing Blog (test behavior; DAMP not DRY): https://testing.googleblog.com/
- Stack Overflow blog, best practices for code comments: https://stackoverflow.blog/2021/12/23/best-practices-for-writing-code-comments
- SonarSource cognitive complexity rule (S3776): https://rules.sonarsource.com/
- OWASP Secure Coding Practices: https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/
