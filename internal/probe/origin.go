// Cross-origin probes, both sent from ForeignOrigin, a site no server should trust. The DNS
// rebinding probe (FR-008) repeats tools/list with that Origin; MCP 2026-07-28 says the server
// MUST answer 403. It carries the user's --header values so servers that demand a token can be
// tested too, but never lets them replace the protocol headers. The CORS preflight (FR-009) is the
// OPTIONS request a browser sends before a cross-site POST with MCP headers; like a browser's, it
// carries no credentials.

package probe

import (
	"context"
	"net/http"
)

const ForeignOrigin = "https://evil.example"

func (p *prober) foreignOriginToolsList(ctx context.Context, endpoint string) (*Exchange, error) {
	req, err := newToolsListRequest(ctx, endpoint, p.toolsBody)
	if err != nil {
		return nil, err
	}
	for name, values := range p.opts.Headers {
		if req.Header.Get(name) == "" {
			req.Header[name] = values
		}
	}
	req.Header.Set("Origin", ForeignOrigin)
	return p.send(req)
}

func (p *prober) preflight(ctx context.Context, endpoint string) (*Exchange, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", ForeignOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type, mcp-method, mcp-protocol-version")
	return p.send(req)
}
