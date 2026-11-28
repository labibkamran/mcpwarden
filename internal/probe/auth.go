// Authenticated mode (FR-013): with --header values, tools/list is sent once more as the user's
// client, so scope and audience rules can see what a token unlocks. The user's headers never
// replace the protocol headers. If the Authorization header carries a JWT, its aud claim is read
// without verifying the signature: only the audience is kept as evidence, never the token
// (FR-022), and a token that is not a JWT simply has no audience.

package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func (p *prober) authenticatedToolsList(ctx context.Context, endpoint string) (*Exchange, error) {
	req, err := newToolsListRequest(ctx, endpoint, p.toolsBody)
	if err != nil {
		return nil, err
	}
	p.addUserHeaders(req)
	return p.send(req)
}

func (p *prober) addUserHeaders(req *http.Request) {
	for name, values := range p.opts.Headers {
		if req.Header.Get(name) == "" {
			req.Header[name] = values
		}
	}
}

func tokenAudience(authorization string) []string {
	scheme, token, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "bearer") {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var claims struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	var one string
	if json.Unmarshal(claims.Aud, &one) == nil && one != "" {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(claims.Aud, &many)
	return many
}
