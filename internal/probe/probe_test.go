package probe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

func collect(t *testing.T, url string, opts probe.Options) (*probe.Evidence, error) {
	t.Helper()
	tgt, err := target.ParseURL(url)
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", url, err)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	return probe.Collect(context.Background(), tgt, opts)
}

func TestCollectToolsList(t *testing.T) {
	open := mockserver.Secure()
	open.RequireAuth = false
	openSSE := open
	openSSE.SSE = true
	tests := []struct {
		name       string
		cfg        mockserver.Config
		wantStatus int
		wantListed bool
		wantTools  int
	}{
		{name: "open server lists tools", cfg: open, wantStatus: http.StatusOK, wantListed: true, wantTools: 2},
		{name: "open server over sse", cfg: openSSE, wantStatus: http.StatusOK, wantListed: true, wantTools: 2},
		{name: "secure server demands a token", cfg: mockserver.Secure(), wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockserver.New(tt.cfg)
			defer srv.Close()

			ev, err := collect(t, srv.URL+mockserver.Path, probe.Options{})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if ev.ToolsList.Status != tt.wantStatus || ev.ToolsListed != tt.wantListed || len(ev.Tools) != tt.wantTools {
				t.Errorf("status %d listed %v tools %d; want %d %v %d",
					ev.ToolsList.Status, ev.ToolsListed, len(ev.Tools), tt.wantStatus, tt.wantListed, tt.wantTools)
			}
		})
	}
}

type recorder struct {
	mu   sync.Mutex
	seen []*http.Request
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.seen = append(rec.seen, &http.Request{Method: r.Method, Header: r.Header.Clone()})
	w.WriteHeader(http.StatusUnauthorized)
}

func (rec *recorder) find(method, origin string) http.Header {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, r := range rec.seen {
		if r.Method == method && r.Header.Get("Origin") == origin {
			return r.Header
		}
	}
	return http.Header{}
}

func TestCollectSendsMCPHeaders(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	_, err := collect(t, srv.URL, probe.Options{UserAgent: "mcpwarden/test"})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	got := rec.find(http.MethodPost, "")
	want := map[string]string{
		"Mcp-Protocol-Version": probe.ProtocolVersion,
		"Mcp-Method":           "tools/list",
		"Accept":               "application/json, text/event-stream",
		"User-Agent":           "mcpwarden/test",
		"Authorization":        "",
	}
	for name, value := range want {
		if got.Get(name) != value {
			t.Errorf("header %s = %q, want %q", name, got.Get(name), value)
		}
	}
}

func TestCollectRecognizesMCPAnswers(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        bool
	}{
		{name: "401 challenge", status: http.StatusUnauthorized, want: true},
		{name: "403 refusal", status: http.StatusForbidden, want: true},
		{name: "json-rpc result", status: http.StatusOK, contentType: "application/json", body: `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, want: true},
		{name: "json-rpc error for an unsupported version", status: http.StatusBadRequest, contentType: "application/json", body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32602}}`, want: true},
		{name: "json-rpc result over sse", status: http.StatusOK, contentType: "text/event-stream", body: "data: {\"jsonrpc\":\"2.0\",\"result\":{}}\n\n", want: true},
		{name: "html 404 page", status: http.StatusNotFound, contentType: "text/html", body: "<pre>Cannot POST /</pre>"},
		{name: "empty 200", status: http.StatusOK},
		{name: "json without jsonrpc 2.0", status: http.StatusOK, contentType: "application/json", body: `{"result":{}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.mu.Lock()
				rec.seen = append(rec.seen, r)
				rec.mu.Unlock()
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			ev, err := collect(t, srv.URL, probe.Options{})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if ev.SpeaksMCP != tt.want {
				t.Errorf("SpeaksMCP = %v, want %v", ev.SpeaksMCP, tt.want)
			}
			if !tt.want && len(rec.seen) != 1 {
				t.Errorf("sent %d requests to a non-MCP URL, want only the first", len(rec.seen))
			}
		})
	}
}

func TestCollectUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	_, err := collect(t, url, probe.Options{})

	if err == nil || !strings.Contains(err.Error(), "tools/list") {
		t.Errorf("Collect error = %v, want a tools/list network error", err)
	}
}

func TestCollectTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	_, err := collect(t, srv.URL, probe.Options{Timeout: 50 * time.Millisecond})

	if err == nil {
		t.Error("Collect succeeded against a server that never answers, want a timeout error")
	}
}

func TestCollectCapsBodyAt1MB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 2<<20)))
	}))
	defer srv.Close()

	ev, err := collect(t, srv.URL, probe.Options{})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if !ev.ToolsList.Truncated || len(ev.ToolsList.Body) != 1<<20 {
		t.Errorf("truncated = %v, body = %d bytes; want true, 1 MB", ev.ToolsList.Truncated, len(ev.ToolsList.Body))
	}
}

func TestCollectRedirects(t *testing.T) {
	other := mockserver.New(mockserver.Config{})
	defer other.Close()
	tests := []struct {
		name       string
		location   func(self string) string
		wantStatus int
	}{
		{name: "same-host redirect is followed", location: func(self string) string { return self + "/final" }, wantStatus: http.StatusOK},
		{name: "cross-host redirect is not followed", location: func(string) string { return other.URL + mockserver.Path }, wantStatus: http.StatusTemporaryRedirect},
		{name: "redirect loop stops after 3", location: func(self string) string { return self + "/" }, wantStatus: http.StatusTemporaryRedirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var self string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/final" {
					return
				}
				w.Header().Set("Location", tt.location(self))
				w.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer srv.Close()
			self = srv.URL

			ev, err := collect(t, srv.URL, probe.Options{})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if ev.ToolsList.Status != tt.wantStatus {
				t.Errorf("status = %d, want %d", ev.ToolsList.Status, tt.wantStatus)
			}
		})
	}
}
