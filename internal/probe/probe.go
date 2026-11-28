// Package probe collects evidence about one MCP server with read-only requests. It is the only
// package that touches the network (SRS 6.1). The first request is an unauthenticated tools/list
// (FR-007); if it fails at the network level the target is unreachable (FR-014) and Collect
// returns an error. Later probes that fail leave their field nil and add to ProbeErrors, because
// checks treat missing evidence as "cannot tell", never as a finding.
package probe

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labibkamran/mcpwarden/internal/target"
)

type Options struct {
	Timeout       time.Duration
	UserAgent     string
	ClientVersion string
	Headers       http.Header
}

type Evidence struct {
	Target        target.Target
	ToolsList     *Exchange
	Tools         []Tool
	ToolsListed   bool
	ForeignOrigin *Exchange
	Preflight     *Exchange
	ProbeErrors   []error
}

type prober struct {
	client    *http.Client
	opts      Options
	toolsBody []byte
}

func Collect(ctx context.Context, t target.Target, opts Options) (*Evidence, error) {
	p := &prober{client: newClient(opts.Timeout), opts: opts, toolsBody: toolsListBody(opts.ClientVersion)}
	endpoint := t.URL.String()

	toolsList, err := p.unauthenticatedToolsList(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	ev := &Evidence{Target: t, ToolsList: toolsList}
	ev.Tools, ev.ToolsListed = DecodeToolsList(toolsList.Header.Get("Content-Type"), toolsList.Body)

	ev.ForeignOrigin, err = p.foreignOriginToolsList(ctx, endpoint)
	ev.note("foreign-origin tools/list", err)
	ev.Preflight, err = p.preflight(ctx, endpoint)
	ev.note("CORS preflight", err)
	return ev, nil
}

func (ev *Evidence) note(probeName string, err error) {
	if err != nil {
		ev.ProbeErrors = append(ev.ProbeErrors, fmt.Errorf("%s: %w", probeName, err))
	}
}

func (p *prober) unauthenticatedToolsList(ctx context.Context, endpoint string) (*Exchange, error) {
	req, err := newToolsListRequest(ctx, endpoint, p.toolsBody)
	if err != nil {
		return nil, err
	}
	return p.send(req)
}

func (p *prober) send(req *http.Request) (*Exchange, error) {
	req.Header.Set("User-Agent", p.opts.UserAgent)
	return send(p.client, req)
}
