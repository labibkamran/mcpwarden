package engine_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

func mustTargets(t *testing.T, urls ...string) []target.Target {
	t.Helper()
	var targets []target.Target
	for _, u := range urls {
		tgt, err := target.ParseURL(u)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", u, err)
		}
		targets = append(targets, tgt)
	}
	return targets
}

func options(concurrency int) engine.Options {
	return engine.Options{Concurrency: concurrency, Probe: probe.Options{Timeout: 5 * time.Second}, Checks: check.Catalog()}
}

func describe(results []engine.Result) []string {
	var lines []string
	for _, r := range results {
		lines = append(lines, fmt.Sprintf("%s grade=%q findings=%d err=%v", r.Status, r.Grade, len(r.Findings), r.Err != nil))
	}
	return lines
}

func TestRunKeepsOrderAndReportsUnreachable(t *testing.T) {
	open := mockserver.Secure()
	open.RequireAuth = false
	vulnerable := mockserver.New(open)
	defer vulnerable.Close()
	secure := mockserver.New(mockserver.Secure())
	defer secure.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	notMCP := httptest.NewServer(http.NotFoundHandler())
	defer notMCP.Close()
	targets := mustTargets(t, vulnerable.URL+mockserver.Path, goneURL, secure.URL+mockserver.Path, notMCP.URL)

	results := engine.Run(context.Background(), targets, options(2))

	want := []string{
		`scanned grade="D" findings=1 err=false`,
		`unreachable grade="" findings=0 err=true`,
		`scanned grade="A" findings=0 err=false`,
		`not-mcp grade="" findings=0 err=true`,
	}
	if got := describe(results); !slices.Equal(got, want) {
		t.Errorf("results =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

type gauge struct {
	mu      sync.Mutex
	current int
	peak    int
}

func (g *gauge) enter() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current++
	g.peak = max(g.peak, g.current)
	return g.current
}

func (g *gauge) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.current--
}

func (g *gauge) max() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}

func TestRunRespectsConcurrency(t *testing.T) {
	inFlight := &gauge{}
	bothIn := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get("Origin") == "" {
			if inFlight.enter() == 2 {
				once.Do(func() { close(bothIn) })
			}
			defer inFlight.leave()
			select {
			case <-bothIn:
			case <-time.After(5 * time.Second):
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	targets := mustTargets(t, srv.URL+"/a", srv.URL+"/b", srv.URL+"/c", srv.URL+"/d", srv.URL+"/e", srv.URL+"/f")

	engine.Run(context.Background(), targets, options(2))

	if got := inFlight.max(); got != 2 {
		t.Errorf("peak concurrent scans = %d, want exactly 2", got)
	}
}
