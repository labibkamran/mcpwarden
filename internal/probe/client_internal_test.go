// Internal test: Collect only ever builds read-only requests, so the transport guard that refuses
// anything else (FR-011) cannot be reached through the public API and is tested directly here.

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadOnlyTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	tests := []struct {
		name      string
		method    string
		mcpMethod string
		wantErr   bool
	}{
		{name: "GET is allowed", method: http.MethodGet},
		{name: "OPTIONS is allowed", method: http.MethodOptions},
		{name: "POST tools/list is allowed", method: http.MethodPost, mcpMethod: "tools/list"},
		{name: "POST tools/call is refused", method: http.MethodPost, mcpMethod: "tools/call", wantErr: true},
		{name: "POST without Mcp-Method is refused", method: http.MethodPost, wantErr: true},
		{name: "DELETE is refused", method: http.MethodDelete, wantErr: true},
		{name: "PUT is refused", method: http.MethodPut, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), tt.method, srv.URL, nil)
			req.Header.Set("Mcp-Method", tt.mcpMethod)

			resp, err := newClient(0).Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}

			if got := errors.Is(err, errNotReadOnly); got != tt.wantErr {
				t.Errorf("refused = %v (err %v), want %v", got, err, tt.wantErr)
			}
		})
	}
}
