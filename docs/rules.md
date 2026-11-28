# mcpwarden rules

Every finding in a mcpwarden report links to its rule's section on this page. Rules are judged only on evidence the scanner collected with read-only requests. When a probe cannot tell, for example because a request failed, the rule stays silent rather than guessing.

Severities set the grade (critical −40, high −20, medium −10, low −5 from 100 points; A = 100, B ≥ 90, C ≥ 75, D ≥ 60, otherwise F) and decide the exit code against `--fail-on`. OWASP labels refer to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (2025, beta).

| ID | Severity | Rule |
|---|---|---|
| [MW001](#mw001) | critical | No authentication required |
| [MW002](#mw002) | high | Host/Origin not validated (DNS rebinding) |
| [MW003](#mw003) | medium | Wildcard CORS |
| [MW004](#mw004) | medium | Missing protected resource metadata |
| [MW005](#mw005) | high | PKCE S256 not advertised |
| [MW006](#mw006) | medium | No issuer identification |
| [MW007](#mw007) | critical | Data-changing tool without auth |
| [MW008](#mw008) | high | Dangerous STDIO command |
| [MW009](#mw009) | high | Plaintext secret in config |
| [MW010](#mw010) | high | Plain HTTP endpoint |
| [MW011](#mw011) | high | Token audience not bound (opt-in) |
| [MW012](#mw012) | medium | No per-tool scopes (opt-in) |

MW008 and MW009 read MCP client config files (`--config`) and never run the commands in them. MW011 and MW012 need a token (`--header`) and are opt-in: turn them on with `--enable MW011` or `--enable MW012`.

## MW001

**No authentication required** · critical · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether the server answers an MCP request from a client that sent no credentials.

**Why it matters.** Anyone who can reach the URL can list and call the server's tools, including tools that read data or change it.

**How it is detected.** mcpwarden sends `tools/list` with no `Authorization` header. A `2xx` answer that carries a JSON-RPC result is a finding, even when the tool list is empty, because the endpoint itself is open.

**Fix.** Require OAuth 2.1 bearer tokens on every request and answer `401 Unauthorized` without one, with a `WWW-Authenticate` header that points to your protected resource metadata (see [MW004](#mw004)).

## MW002

**Host/Origin not validated (DNS rebinding)** · high · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether the server rejects requests whose `Origin` header names a site it does not trust.

**Why it matters.** With DNS rebinding, a malicious web page can make a user's browser send requests to a server on their machine or network. The MCP specification requires servers to validate `Origin` and answer `403 Forbidden` when it is invalid.

**How it is detected.** mcpwarden repeats `tools/list` with `Origin: https://evil.example`. Any `2xx` answer is a finding. A `401` proves nothing, because the server may check the token before the origin; pass a token with `--header "Authorization: Bearer …"` so the probe gets past authentication.

**Fix.** Answer `403` to any request whose `Origin` is not on an allow-list. Bind servers that run locally to `127.0.0.1`, not `0.0.0.0`.

## MW003

**Wildcard CORS** · medium · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether the server's CORS policy lets any website call it from a browser.

**Why it matters.** A permissive CORS policy lets scripts on any site send requests to the server and read the answers. Echoing the caller's `Origin` back is worse than `*`, because browsers then also allow requests that carry credentials.

**How it is detected.** mcpwarden sends the `OPTIONS` preflight a browser would send before a cross-site `POST` from `https://evil.example`. A finding is an `Access-Control-Allow-Origin` of `*` or of `https://evil.example`.

**Fix.** Answer preflights only for origins you know, and never with `*` or by copying the request's `Origin`.

## MW004

**Missing protected resource metadata** · medium · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether a server that demands authentication tells clients where to get a token.

**Why it matters.** MCP clients discover the authorization server through RFC 9728 protected resource metadata. Without it, standard clients cannot sign in, and operators are tempted to fall back to long-lived static keys.

**How it is detected.** It applies only when the unauthenticated `tools/list` got `401` or `403`; an open server is reported as [MW001](#mw001). mcpwarden looks in the order the MCP specification gives: the `resource_metadata` URL in `WWW-Authenticate`, then `/.well-known/oauth-protected-resource` with the endpoint path appended, then the root. It is a finding only when every location answered and none held a document with a `resource` field; a network failure is never counted as missing.

**Fix.** Publish RFC 9728 metadata at `/.well-known/oauth-protected-resource` (for an endpoint at `/mcp`, at `/.well-known/oauth-protected-resource/mcp`) listing your `authorization_servers`, and point to it from the `resource_metadata` parameter of your `401` responses.

## MW005

**PKCE S256 not advertised** · high · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether the authorization server supports PKCE with the `S256` method.

**Why it matters.** Without PKCE, an attacker who intercepts an authorization code can exchange it for a token. The MCP specification tells clients to refuse an authorization server whose metadata lacks `code_challenge_methods_supported`.

**How it is detected.** mcpwarden reads the first authorization server from the protected resource metadata and fetches its RFC 8414 or OpenID Connect metadata, in the order the MCP specification gives. It is a finding when `code_challenge_methods_supported` is absent or does not include `S256`. The rule is judged only when that metadata was found.

**Fix.** Enable PKCE with `S256` on the authorization server and list it in `code_challenge_methods_supported`.

## MW006

**No issuer identification** · medium · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether the authorization server says it returns the `iss` parameter in authorization responses (RFC 9207).

**Why it matters.** A client that works with several authorization servers needs `iss` to know which one answered. Without it, a malicious authorization server can trick the client into sending a code meant for an honest one to the wrong place (a mix-up attack).

**How it is detected.** mcpwarden reads the authorization server metadata found for [MW005](#mw005). It is a finding when `authorization_response_iss_parameter_supported` is absent or `false`; RFC 9207 treats an absent field as `false`. The rule is judged only when that metadata was found.

**Fix.** Return `iss` in every authorization response and set `authorization_response_iss_parameter_supported` to `true` in the metadata.

## MW007

**Data-changing tool without auth** · critical · MCP07:2025 Insufficient Authentication & Authorization

**What it checks.** Whether a server that answers without a token ([MW001](#mw001)) lists tools that create, change or delete data.

**Why it matters.** An open server that only reads is bad; one whose tools write is worse, because anyone who reaches it can change or destroy what those tools manage.

**How it is detected.** mcpwarden reads the tool list from the unauthenticated `tools/list`. A tool counts as data-changing when its annotations say `destructiveHint: true` or `readOnlyHint: false`, or, when it has no `readOnlyHint`, when the first word of its name is a write verb such as `create`, `delete`, `update`, `send` or `exec` (`create_issue`, `deleteFile`, `DROP_TABLE`). A tool marked `readOnlyHint: true` is never flagged. The evidence names up to five tools. mcpwarden never calls a tool.

**Fix.** Require OAuth 2.1 bearer tokens before listing or calling tools, give data-changing tools their own scopes, and annotate every tool with accurate `readOnlyHint` and `destructiveHint` values.

## MW008

**Dangerous STDIO command** · high · MCP05:2025 Command Injection & Execution

**What it checks.** Whether a config entry starts its server through a command that runs arbitrary code instead of a fixed program.

**Why it matters.** A shell script, a download piped into a shell, or inline interpreter code in a config file runs with the user's rights every time the client starts. Whoever can edit that string, or control the downloaded script, controls the machine.

**How it is detected.** mcpwarden reads the `command` and `args` of each entry as text and never runs them. It is a finding when the command is a shell given a script (`sh`, `bash`, `zsh` and others with `-c`; `cmd /c`; `powershell` or `pwsh` with `-Command` or `-EncodedCommand`), when the command line pipes `curl` or `wget` into a shell, or when an interpreter runs inline code (`python -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`, `deno eval`). Windows paths and `.exe` are recognised. The evidence names the program and flag, never the arguments.

**Fix.** Start the server from a pinned package (`npx -y @scope/server@1.2.3`, `uvx server==1.2.3`) or a fixed binary path, without a shell, a piped download or inline code.

## MW009

**Plaintext secret in config** · high · MCP01:2025 Token Mismanagement & Secret Exposure

**What it checks.** Whether a config file holds an API key or token in plain text.

**Why it matters.** Config files are copied, backed up, synced and committed to repositories. A key written into one can be used by anyone who reads the file, and it has to be rotated once it leaks.

**How it is detected.** mcpwarden matches every `env` value, header value and command argument against well-known key formats: AWS access keys, GitHub tokens, Anthropic, OpenAI, Slack, Stripe live and Google API keys, private keys, JWTs, and literal `Bearer` tokens. `${...}` references such as `${input:token}` or `${env:TOKEN}` are removed first, because they point to a secret store. The evidence says where the secret is and what kind of key it looks like, never the value.

**Fix.** Remove the secret from the file and rotate it. Reference it instead: `${input:token}` in VS Code prompts once and stores it securely, and `${env:TOKEN}` reads it from the environment.

## MW010

**Plain HTTP endpoint** · high · MCP01:2025 Token Mismanagement & Secret Exposure

**What it checks.** Whether the server is reached over `http://` on a host other than this machine.

**Why it matters.** Without TLS, bearer tokens and tool results cross the network in the clear, where anyone on the path can read or change them.

**How it is detected.** mcpwarden reads the scheme and host of each URL argument and config entry. It is a finding for `http://` unless the host is `localhost`, a `*.localhost` name or a loopback address (`127.0.0.0/8`, `::1`). It needs no request, so it is reported even when the server is unreachable. A config `url` built from a `${...}` variable is not judged.

**Fix.** Serve the endpoint over HTTPS (TLS 1.2 or later) and point clients at the `https://` URL.

## MW011

**Token audience not bound** · high · MCP07:2025 Insufficient Authentication & Authorization · opt-in

**What it checks.** Whether the server accepts a token that was issued for a different resource.

**Why it matters.** If a server does not check the token's audience, a token issued for any other service on the same authorization server works here too, and a malicious server that receives a user's token can replay it against this one. The MCP specification requires servers to validate that tokens were issued for them (RFC 8707).

**How it is detected.** Run with `--enable MW011` and `--header "Authorization: Bearer <JWT>"` using a token issued for another resource. mcpwarden sends `tools/list` with it and decodes the token's `aud` claim locally, without verifying it and without printing the token. It is a finding when the server answers with a tool list and the audience matches neither the `resource` in the protected resource metadata, the target URL, nor either one's origin. Opaque (non-JWT) tokens are not judged.

**Fix.** Reject tokens whose `aud` does not name this server's resource, and have clients request tokens with an RFC 8707 `resource` parameter.

## MW012

**No per-tool scopes** · medium · MCP02:2025 Privilege Escalation via Scope Creep · opt-in

**What it checks.** Whether one scope unlocks every tool.

**Why it matters.** With a single scope, a client cannot ask for less than everything: a token meant only to read also lets it write, and a leaked token exposes every tool.

**How it is detected.** Run with `--enable MW012` and a token in `--header`. It is a finding when the protected resource metadata lists exactly one scope in `scopes_supported` and `tools/list` with the token returns two or more tools. An absent `scopes_supported` is not judged, since RFC 9728 makes it optional. The rule is opt-in because a server may still check finer permissions inside each tool.

**Fix.** Define least-privilege scopes, for example read and write per resource, list them in `scopes_supported`, and check them on every tool call.
