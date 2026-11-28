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

Rules MW006 to MW012 arrive in milestone 3.

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
