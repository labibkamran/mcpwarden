package probe_test

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

func TestCollectOAuthMetadataFromMockServer(t *testing.T) {
	open := mockserver.Secure()
	open.RequireAuth = false
	unpublished := mockserver.Secure()
	unpublished.PublishMetadata = false
	tests := []struct {
		name        string
		cfg         mockserver.Config
		wantPRM     bool
		wantMissing bool
		wantPKCE    []string
	}{
		{name: "found through WWW-Authenticate", cfg: mockserver.Secure(), wantPRM: true, wantPKCE: []string{"S256"}},
		{name: "found at the path-inserted well-known URI", cfg: open, wantPRM: true, wantPKCE: []string{"S256"}},
		{name: "confirmed missing", cfg: unpublished, wantMissing: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockserver.New(tt.cfg)
			defer srv.Close()

			ev, err := collect(t, srv.URL+mockserver.Path, probe.Options{})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if (ev.ResourceMetadata != nil) != tt.wantPRM || ev.ResourceMetadataMissing != tt.wantMissing {
				t.Errorf("metadata found %v, missing %v; want %v, %v", ev.ResourceMetadata != nil, ev.ResourceMetadataMissing, tt.wantPRM, tt.wantMissing)
			}
			if got := pkceMethods(ev); !slices.Equal(got, tt.wantPKCE) {
				t.Errorf("PKCE methods = %q, want %q", got, tt.wantPKCE)
			}
		})
	}
}

func TestCollectOAuthMetadataFallbacks(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/oauth-protected-resource":
			writeTestJSON(w, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/tenant1"}})
		case "/tenant1/.well-known/openid-configuration":
			writeTestJSON(w, map[string]any{"issuer": base + "/tenant1", "code_challenge_methods_supported": []string{"plain"}})
		case "/.well-known/oauth-protected-resource/mcp":
			_, _ = w.Write([]byte("<html>not json</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	base = srv.URL

	ev, err := collect(t, srv.URL+"/mcp", probe.Options{})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if ev.ResourceMetadata == nil || ev.AuthServerMetadata == nil {
		t.Fatalf("resource metadata %v, auth server metadata %v; want both found through fallbacks", ev.ResourceMetadata, ev.AuthServerMetadata)
	}
	if got := pkceMethods(ev); !slices.Equal(got, []string{"plain"}) {
		t.Errorf("PKCE methods = %q, want [plain]", got)
	}
}

func TestCollectSkipsResourceMetadataOnAnotherOrigin(t *testing.T) {
	other := &recorder{}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+otherSrv.URL+`/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ev, err := collect(t, srv.URL+"/mcp", probe.Options{})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if len(other.seen) != 0 || !ev.ResourceMetadataMissing {
		t.Errorf("requests to the other origin = %d, missing = %v; want 0 and true", len(other.seen), ev.ResourceMetadataMissing)
	}
}

func TestCollectMetadataNetworkErrorIsNotMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.(*net.TCPConn).Close()
	}))
	defer srv.Close()

	ev, err := collect(t, srv.URL+"/mcp", probe.Options{})

	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if ev.ResourceMetadataMissing || len(ev.ProbeErrors) == 0 {
		t.Errorf("missing = %v, probe errors = %v; want false and a noted error", ev.ResourceMetadataMissing, ev.ProbeErrors)
	}
}

func pkceMethods(ev *probe.Evidence) []string {
	if ev.AuthServerMetadata == nil {
		return nil
	}
	return ev.AuthServerMetadata.CodeChallengeMethodsSupported
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
