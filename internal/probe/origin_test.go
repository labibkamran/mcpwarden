package probe_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

var withToken = probe.Options{Headers: http.Header{"Authorization": {"Bearer " + mockserver.Token}}}

func TestCollectForeignOrigin(t *testing.T) {
	trusting := mockserver.Secure()
	trusting.ValidateOrigin = false
	tests := []struct {
		name       string
		cfg        mockserver.Config
		opts       probe.Options
		wantStatus int
	}{
		{name: "origin-validating server answers 403", cfg: mockserver.Secure(), opts: withToken, wantStatus: http.StatusForbidden},
		{name: "trusting server accepts the foreign origin", cfg: trusting, opts: withToken, wantStatus: http.StatusOK},
		{name: "without a token the auth check answers first", cfg: trusting, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockserver.New(tt.cfg)
			defer srv.Close()

			ev, err := collect(t, srv.URL+mockserver.Path, tt.opts)

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if ev.ForeignOrigin.Status != tt.wantStatus {
				t.Errorf("foreign-origin status = %d, want %d", ev.ForeignOrigin.Status, tt.wantStatus)
			}
		})
	}
}

func TestCollectPreflight(t *testing.T) {
	tests := []struct {
		name        string
		allowOrigin string
		want        string
	}{
		{name: "no cors headers", allowOrigin: "", want: ""},
		{name: "wildcard", allowOrigin: "*", want: "*"},
		{name: "reflected origin", allowOrigin: "reflect", want: probe.ForeignOrigin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := mockserver.Secure()
			cfg.AllowOrigin = tt.allowOrigin
			srv := mockserver.New(cfg)
			defer srv.Close()

			ev, err := collect(t, srv.URL+mockserver.Path, probe.Options{})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if got := ev.Preflight.Header.Get("Access-Control-Allow-Origin"); got != tt.want {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCollectCrossOriginHeaders(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	opts := probe.Options{Headers: http.Header{
		"Authorization": {"Bearer t"},
		"Mcp-Method":    {"tools/call"},
	}}

	_, err := collect(t, srv.URL, opts)

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	unauth := rec.find(http.MethodPost, "")
	foreign := rec.find(http.MethodPost, probe.ForeignOrigin)
	preflight := rec.find(http.MethodOptions, probe.ForeignOrigin)
	if unauth.Get("Authorization") != "" {
		t.Error("unauthenticated tools/list carried the user's Authorization header")
	}
	if foreign.Get("Authorization") != "Bearer t" || foreign.Get("Mcp-Method") != "tools/list" {
		t.Errorf("foreign-origin probe: Authorization %q, Mcp-Method %q; want the user's token and tools/list",
			foreign.Get("Authorization"), foreign.Get("Mcp-Method"))
	}
	if preflight.Get("Authorization") != "" || preflight.Get("Access-Control-Request-Method") != http.MethodPost {
		t.Errorf("preflight: Authorization %q, request method %q; want no credentials and POST",
			preflight.Get("Authorization"), preflight.Get("Access-Control-Request-Method"))
	}
}

func TestCollectNotesFailedProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.(*net.TCPConn).Close()
	}))
	defer srv.Close()

	ev, err := collect(t, srv.URL, probe.Options{})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if ev.Preflight != nil || len(ev.ProbeErrors) != 1 || !strings.HasPrefix(ev.ProbeErrors[0].Error(), "CORS preflight") {
		t.Errorf("Preflight = %v, ProbeErrors = %v; want nil and one CORS preflight error", ev.Preflight, ev.ProbeErrors)
	}
}
