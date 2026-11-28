// Package probe collects evidence about one MCP server with read-only requests. It is the only
// package that touches the network (SRS 6.1). The first request is an unauthenticated tools/list
// (FR-007); if it fails at the network level the target is unreachable (FR-014) and Collect
// returns an error. If its answer does not speak MCP, SpeaksMCP is false and no further request
// is sent, because nothing at the URL can be judged. Later probes that fail leave their field nil
// and add to ProbeErrors, because checks treat missing evidence as "cannot tell", never as a
// finding. ResourceMetadataMissing is true only when every metadata location answered and none
// held a document. With --header values the tools are also listed as the user's client (auth.go).
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
	SpeaksMCP     bool
	ForeignOrigin *Exchange
	Preflight     *Exchange

	AuthToolsList   *Exchange
	AuthTools       []Tool
	AuthToolsListed bool
	TokenAudience   []string

	ResourceMetadata        *ResourceMetadata
	ResourceMetadataMissing bool
	AuthServerMetadata      *AuthServerMetadata

	ProbeErrors []error
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
	if ev.SpeaksMCP = speaksMCP(toolsList); !ev.SpeaksMCP {
		return ev, nil
	}

	ev.ForeignOrigin, err = p.foreignOriginToolsList(ctx, endpoint)
	ev.note("foreign-origin tools/list", err)
	ev.Preflight, err = p.preflight(ctx, endpoint)
	ev.note("CORS preflight", err)
	if len(p.opts.Headers) > 0 {
		p.collectAuthenticated(ctx, endpoint, ev)
	}

	ev.ResourceMetadata, err = p.resourceMetadata(ctx, t.URL, toolsList)
	ev.note("protected resource metadata", err)
	ev.ResourceMetadataMissing = ev.ResourceMetadata == nil && err == nil
	ev.AuthServerMetadata, err = p.authServerMetadata(ctx, ev.ResourceMetadata)
	ev.note("authorization server metadata", err)
	return ev, nil
}

func (p *prober) collectAuthenticated(ctx context.Context, endpoint string, ev *Evidence) {
	answer, err := p.authenticatedToolsList(ctx, endpoint)
	ev.note("authenticated tools/list", err)
	if answer != nil {
		ev.AuthToolsList = answer
		ev.AuthTools, ev.AuthToolsListed = DecodeToolsList(answer.Header.Get("Content-Type"), answer.Body)
	}
	ev.TokenAudience = tokenAudience(p.opts.Headers.Get("Authorization"))
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
