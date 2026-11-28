package probe_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/test/mockserver"
)

func jwt(payload string) string {
	part := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return part(`{"alg":"none"}`) + "." + part(payload) + "." + part("signature")
}

func TestCollectListsToolsWithTheUsersToken(t *testing.T) {
	tests := []struct {
		name       string
		opts       probe.Options
		wantStatus int
		wantTools  int
	}{
		{name: "with a token", opts: withToken, wantStatus: http.StatusOK, wantTools: 2},
		{name: "with a wrong token", opts: probe.Options{Headers: http.Header{"Authorization": {"Bearer wrong"}}}, wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := mockserver.New(mockserver.Secure())
			defer srv.Close()

			ev, err := collect(t, srv.URL+mockserver.Path, tt.opts)

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if ev.AuthToolsList == nil || ev.AuthToolsList.Status != tt.wantStatus || len(ev.AuthTools) != tt.wantTools {
				t.Errorf("authenticated tools/list = %+v with %d tools, want status %d and %d tools",
					ev.AuthToolsList, len(ev.AuthTools), tt.wantStatus, tt.wantTools)
			}
		})
	}
}

func TestCollectAuthenticatedModeCostsOneRequest(t *testing.T) {
	without, with := &recorder{}, &recorder{}
	srvWithout, srvWith := httptest.NewServer(without), httptest.NewServer(with)
	defer srvWithout.Close()
	defer srvWith.Close()

	evWithout, errWithout := collect(t, srvWithout.URL, probe.Options{})
	_, errWith := collect(t, srvWith.URL, withToken)

	if errWithout != nil || errWith != nil {
		t.Fatalf("Collect errors: %v, %v", errWithout, errWith)
	}
	if evWithout.AuthToolsList != nil || len(with.seen) != len(without.seen)+1 {
		t.Errorf("without headers: authenticated tools/list %v; requests %d with a token vs %d without, want nil and exactly one more",
			evWithout.AuthToolsList, len(with.seen), len(without.seen))
	}
}

func TestCollectReadsTheTokenAudience(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		want          []string
	}{
		{name: "single audience", authorization: "Bearer " + jwt(`{"aud":"https://mcp.example/mcp"}`), want: []string{"https://mcp.example/mcp"}},
		{name: "audience list", authorization: "bearer " + jwt(`{"aud":["a","b"]}`), want: []string{"a", "b"}},
		{name: "no aud claim", authorization: "Bearer " + jwt(`{"sub":"u"}`)},
		{name: "opaque token", authorization: "Bearer opaque-token"},
		{name: "payload is not json", authorization: "Bearer a.bm90LWpzb24.c"},
		{name: "payload is not base64", authorization: "Bearer a.!!!.c"},
		{name: "basic credentials", authorization: "Basic dXNlcjpwYXNz"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(&recorder{})
			defer srv.Close()

			ev, err := collect(t, srv.URL, probe.Options{Headers: http.Header{"Authorization": {tt.authorization}}})

			if err != nil {
				t.Fatalf("Collect error: %v", err)
			}
			if !slices.Equal(ev.TokenAudience, tt.want) {
				t.Errorf("TokenAudience = %q, want %q", ev.TokenAudience, tt.want)
			}
		})
	}
}
