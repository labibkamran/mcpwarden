// Package mockserver runs a configurable MCP server for tests (SRS 13.1). Secure returns the
// configuration that triggers no rule; each rule's vulnerable server differs from it in one
// setting, so a test proves both the finding and the absence of false positives. It speaks just
// enough MCP 2026-07-28 Streamable HTTP for the probes: tools/list over POST (JSON or SSE), CORS
// preflight over OPTIONS, RFC 9728 protected resource metadata and RFC 8414 authorization server
// metadata. AllowOrigin "*" answers preflights with a wildcard and "reflect" echoes the caller's
// Origin. PKCEMethods nil leaves code_challenge_methods_supported out of the metadata, and
// IssParameter false leaves out authorization_response_iss_parameter_supported (RFC 9207).
package mockserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

const (
	Path          = "/mcp"
	Token         = "test-token"
	TrustedOrigin = "https://app.example"
)

type Config struct {
	RequireAuth     bool
	ValidateOrigin  bool
	AllowOrigin     string
	PublishMetadata bool
	PKCEMethods     []string
	IssParameter    bool
	SSE             bool
}

func Secure() Config {
	return Config{
		RequireAuth:     true,
		ValidateOrigin:  true,
		PublishMetadata: true,
		PKCEMethods:     []string{"S256"},
		IssParameter:    true,
	}
}

type server struct {
	cfg     Config
	baseURL string
}

func New(cfg Config) *httptest.Server {
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	s := &server{cfg: cfg, baseURL: "http://" + srv.Listener.Addr().String()}
	mux.HandleFunc("POST "+Path, s.handleMCP)
	mux.HandleFunc("OPTIONS "+Path, s.handlePreflight)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource"+Path, s.handleResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleAuthServerMetadata)
	srv.Start()
	return srv
}

func (s *server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ValidateOrigin && !isTrustedOrigin(r.Header.Get("Origin")) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if s.cfg.RequireAuth && r.Header.Get("Authorization") != "Bearer "+Token {
		s.challenge(w)
		return
	}
	if r.Header.Get("Mcp-Method") != "tools/list" {
		http.Error(w, "unsupported method", http.StatusBadRequest)
		return
	}
	s.writeTools(w)
}

func isTrustedOrigin(origin string) bool {
	return origin == "" || origin == TrustedOrigin
}

func (s *server) challenge(w http.ResponseWriter) {
	value := "Bearer"
	if s.cfg.PublishMetadata {
		value += ` resource_metadata="` + s.baseURL + "/.well-known/oauth-protected-resource" + Path + `"`
	}
	w.Header().Set("WWW-Authenticate", value)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (s *server) writeTools(w http.ResponseWriter) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{"tools": []map[string]any{
			{"name": "search_files", "annotations": map[string]any{"readOnlyHint": true}},
			{"name": "delete_file", "annotations": map[string]any{"destructiveHint": true}},
		}},
	})
	if s.cfg.SSE {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(append(append([]byte("event: message\ndata: "), body...), "\n\n"...))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (s *server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	switch s.cfg.AllowOrigin {
	case "*":
		w.Header().Set("Access-Control-Allow-Origin", "*")
	case "reflect":
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.PublishMetadata {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, map[string]any{
		"resource":              s.baseURL + Path,
		"authorization_servers": []string{s.baseURL},
	})
}

func (s *server) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	if !s.cfg.PublishMetadata {
		http.NotFound(w, nil)
		return
	}
	metadata := map[string]any{
		"issuer":                 s.baseURL,
		"authorization_endpoint": s.baseURL + "/authorize",
		"token_endpoint":         s.baseURL + "/token",
	}
	if s.cfg.PKCEMethods != nil {
		metadata["code_challenge_methods_supported"] = s.cfg.PKCEMethods
	}
	if s.cfg.IssParameter {
		metadata["authorization_response_iss_parameter_supported"] = true
	}
	writeJSON(w, metadata)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
