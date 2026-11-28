package probe_test

import (
	"slices"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestDecodeToolsList(t *testing.T) {
	const result = `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"},{"name":"b"}]}}`
	tests := []struct {
		name        string
		contentType string
		body        string
		wantNames   []string
		wantOK      bool
	}{
		{name: "json result", contentType: "application/json", body: result, wantNames: []string{"a", "b"}, wantOK: true},
		{name: "json with charset", contentType: "application/json; charset=utf-8", body: result, wantNames: []string{"a", "b"}, wantOK: true},
		{name: "sse first event", contentType: "text/event-stream", body: "event: message\ndata: " + result + "\n\n", wantNames: []string{"a", "b"}, wantOK: true},
		{name: "sse with crlf", contentType: "text/event-stream", body: "event: message\r\ndata: " + result + "\r\n\r\n", wantNames: []string{"a", "b"}, wantOK: true},
		{name: "sse data split over lines", contentType: "text/event-stream", body: "data: {\"result\":\ndata: {\"tools\":[]}}\n\n", wantOK: true},
		{name: "empty tool list is a result", contentType: "application/json", body: `{"result":{"tools":[]}}`, wantOK: true},
		{name: "json-rpc error", contentType: "application/json", body: `{"error":{"code":-32601,"message":"no"}}`},
		{name: "html page", contentType: "text/html", body: "<html>login</html>"},
		{name: "empty body", contentType: "application/json", body: ""},
		{name: "sse without data", contentType: "text/event-stream", body: "event: ping\n\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools, ok := probe.DecodeToolsList(tt.contentType, []byte(tt.body))

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got := toolNames(tools); !slices.Equal(got, tt.wantNames) {
				t.Errorf("tools = %q, want %q", got, tt.wantNames)
			}
		})
	}
}

func toolNames(tools []probe.Tool) []string {
	var names []string
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
