// End-to-end rule tests (SRS 13.1, 13.2): each rule is detected on a mock server that differs
// from the secure configuration in one setting, and the secure server yields no finding at all.
// Each case asserts the exact set of findings, so a rule that fires where it should not breaks
// the test as surely as one that misses.

package integration_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

var (
	token         = http.Header{"Authorization": {"Bearer " + mockserver.Token}}
	foreignJWT    = http.Header{"Authorization": {"Bearer " + jwtFor("https://other.example/mcp")}}
	encodeSegment = base64.RawURLEncoding.EncodeToString
)

func jwtFor(audience string) string {
	return encodeSegment([]byte(`{"alg":"none"}`)) + "." + encodeSegment([]byte(`{"aud":"`+audience+`"}`)) + ".sig"
}

func secureWith(change func(*mockserver.Config)) mockserver.Config {
	cfg := mockserver.Secure()
	change(&cfg)
	return cfg
}

func scanIDs(t *testing.T, cfg mockserver.Config, headers http.Header) []string {
	t.Helper()
	srv := mockserver.New(cfg)
	defer srv.Close()
	tgt, err := target.ParseURL(srv.URL + mockserver.Path)
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	opts := engine.Options{
		Concurrency: 1,
		Checks:      check.Catalog(),
		Probe:       probe.Options{Timeout: 5 * time.Second, Headers: headers},
	}

	result := engine.Run(context.Background(), []target.Target{tgt}, opts)[0]

	if result.Status != engine.StatusScanned || len(result.Notes) != 0 {
		t.Fatalf("status %s, notes %v; want a clean scan", result.Status, result.Notes)
	}
	var ids []string
	for _, f := range result.Findings {
		ids = append(ids, f.Rule.ID)
	}
	return ids
}

func TestRulesAgainstMockServers(t *testing.T) {
	tests := []struct {
		name    string
		cfg     mockserver.Config
		headers http.Header
		want    []string
	}{
		{name: "secure server without a token", cfg: mockserver.Secure()},
		{name: "secure server with a token", cfg: mockserver.Secure(), headers: token},
		{name: "MW001 open read-only server", cfg: secureWith(func(c *mockserver.Config) { c.RequireAuth = false; c.ReadOnlyTools = true }), want: []string{"MW001"}},
		{name: "MW001 open read-only server over SSE", cfg: secureWith(func(c *mockserver.Config) { c.RequireAuth = false; c.ReadOnlyTools = true; c.SSE = true }), want: []string{"MW001"}},
		{name: "MW007 open server with a destructive tool", cfg: secureWith(func(c *mockserver.Config) { c.RequireAuth = false }), want: []string{"MW001", "MW007"}},
		{name: "MW002 origin not validated", cfg: secureWith(func(c *mockserver.Config) { c.ValidateOrigin = false }), headers: token, want: []string{"MW002"}},
		{name: "MW002 needs a token to get past auth", cfg: secureWith(func(c *mockserver.Config) { c.ValidateOrigin = false })},
		{name: "MW003 wildcard CORS", cfg: secureWith(func(c *mockserver.Config) { c.AllowOrigin = "*" }), want: []string{"MW003"}},
		{name: "MW003 reflected origin", cfg: secureWith(func(c *mockserver.Config) { c.AllowOrigin = "reflect" }), want: []string{"MW003"}},
		{name: "MW004 no protected resource metadata", cfg: secureWith(func(c *mockserver.Config) { c.PublishMetadata = false }), want: []string{"MW004"}},
		{name: "MW011 token for another audience is rejected", cfg: mockserver.Secure(), headers: foreignJWT},
		{name: "MW011 token for another audience is accepted", cfg: secureWith(func(c *mockserver.Config) { c.AcceptAnyToken = true }), headers: foreignJWT, want: []string{"MW011"}},
		{name: "MW005 PKCE methods absent", cfg: secureWith(func(c *mockserver.Config) { c.PKCEMethods = nil }), want: []string{"MW005"}},
		{name: "MW006 no iss parameter", cfg: secureWith(func(c *mockserver.Config) { c.IssParameter = false }), want: []string{"MW006"}},
		{name: "MW005 plain PKCE only", cfg: secureWith(func(c *mockserver.Config) { c.PKCEMethods = []string{"plain"} }), want: []string{"MW005"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scanIDs(t, tt.cfg, tt.headers); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}
