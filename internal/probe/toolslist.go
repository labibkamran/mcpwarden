// The tools/list request (FR-007) and its decoder. MCP 2026-07-28 is stateless: a client sends
// tools/list directly, without an initialize handshake, and the MCP-Protocol-Version and
// Mcp-Method headers must match the method and the protocol version in params._meta. A server
// answers with JSON or with an SSE stream whose first event holds the JSON-RPC response;
// DecodeToolsList reads both and reports whether the response carried a result.

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"net/http"
)

const ProtocolVersion = "2026-07-28"

type Tool struct {
	Name string `json:"name"`
}

func toolsListBody(clientVersion string) []byte {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  readOnlyMethod,
		"params": map[string]any{"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    ProtocolVersion,
			"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "mcpwarden", "version": clientVersion},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}},
	})
	return body
}

func newToolsListRequest(ctx context.Context, url string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", ProtocolVersion)
	req.Header.Set("Mcp-Method", readOnlyMethod)
	return req, nil
}

func DecodeToolsList(contentType string, body []byte) ([]Tool, bool) {
	payload := body
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil && mediaType == "text/event-stream" {
		payload = firstEventData(body)
	}
	var msg struct {
		Result *struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil || msg.Result == nil {
		return nil, false
	}
	return msg.Result.Tools, true
}

func firstEventData(stream []byte) []byte {
	var data [][]byte
	for _, line := range bytes.Split(stream, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 && len(data) > 0 {
			break
		}
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = append(data, bytes.TrimPrefix(value, []byte(" ")))
		}
	}
	return bytes.Join(data, []byte("\n"))
}
