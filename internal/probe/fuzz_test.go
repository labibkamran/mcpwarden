// FuzzDecodeToolsList feeds arbitrary bodies to the JSON-RPC decoder (SRS 13.1): it must never
// panic and must be deterministic. Run longer with: go test -fuzz=FuzzDecodeToolsList ./internal/probe

package probe_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func FuzzDecodeToolsList(f *testing.F) {
	f.Add("application/json", `{"result":{"tools":[{"name":"a"}]}}`)
	f.Add("text/event-stream", "event: message\ndata: {\"result\":{\"tools\":[]}}\n\n")
	f.Add("text/event-stream; charset=utf-8", "data: {\ndata: }\r\n\r\n")
	f.Add("application/json", `{"error":{}}`)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, contentType, body string) {
		tools, ok := probe.DecodeToolsList(contentType, []byte(body))
		again, okAgain := probe.DecodeToolsList(contentType, []byte(body))
		if ok != okAgain || len(tools) != len(again) {
			t.Fatalf("decoding is not deterministic for %q", body)
		}
		if !ok && tools != nil {
			t.Fatalf("returned tools without a result for %q", body)
		}
	})
}
