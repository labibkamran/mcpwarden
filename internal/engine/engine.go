// Package engine scans targets (FR-014, FR-015): for each one it collects evidence, runs the
// selected checks and grades the findings. Up to Concurrency targets run at once, each under a
// 30 s deadline (SRS 10.2), and results keep the input order. A target that cannot be reached is
// reported as unreachable while the others continue (FR-014). One whose answer does not speak MCP
// is reported as not an MCP endpoint instead of being graded, since no rule can judge it.
// Evidence is dropped as soon as the checks return, so memory stays bounded by Concurrency
// (SRS 7.3). The engine knows nothing about how it was invoked, so the CLI and the v2 workers can
// share it.
package engine

import (
	"context"
	"fmt"
	"mime"
	"slices"
	"sync"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/score"
	"github.com/labibkamran/mcpwarden/internal/target"
)

const targetTimeout = 30 * time.Second

type Status string

const (
	StatusScanned     Status = "scanned"
	StatusUnreachable Status = "unreachable"
	StatusNotMCP      Status = "not-mcp"
)

type Options struct {
	Concurrency int
	Probe       probe.Options
	Checks      []check.Check
}

type Result struct {
	Target   target.Target
	Status   Status
	Err      error
	Grade    string
	Findings []check.Finding
	Notes    []error
}

func Run(ctx context.Context, targets []target.Target, opts Options) []Result {
	results := make([]Result, len(targets))
	slots := make(chan struct{}, max(opts.Concurrency, 1))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = scan(ctx, t, opts)
		})
	}
	wg.Wait()
	return results
}

func scan(ctx context.Context, t target.Target, opts Options) Result {
	ctx, cancel := context.WithTimeout(ctx, targetTimeout)
	defer cancel()

	ev, err := probe.Collect(ctx, t, opts.Probe)
	if err != nil {
		return Result{Target: t, Status: StatusUnreachable, Err: err}
	}
	if !ev.SpeaksMCP {
		return Result{Target: t, Status: StatusNotMCP, Err: notMCPError(ev.ToolsList)}
	}
	findings, checkErrs := check.Run(opts.Checks, ev)
	return Result{
		Target:   t,
		Status:   StatusScanned,
		Grade:    score.Grade(findings),
		Findings: findings,
		Notes:    slices.Concat(ev.ProbeErrors, checkErrs),
	}
}

func notMCPError(answer *probe.Exchange) error {
	kind := "no content type"
	if mediaType, _, err := mime.ParseMediaType(answer.Header.Get("Content-Type")); err == nil {
		kind = mediaType
	}
	return fmt.Errorf("tools/list got HTTP %d (%s) instead of an MCP response; check the URL path, which is often /mcp",
		answer.Status, kind)
}
