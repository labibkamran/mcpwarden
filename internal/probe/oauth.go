// OAuth metadata discovery (FR-010) in the order MCP 2026-07-28 prescribes. Protected resource
// metadata (RFC 9728): the resource_metadata URL from the WWW-Authenticate header of the
// unauthenticated response, then the well-known URI with the endpoint path inserted, then the root
// well-known URI. A resource_metadata URL on another origin is skipped so the CLI only contacts
// the target and its authorization server (NFR-009). Authorization server metadata (RFC 8414) for
// the first listed server: oauth-authorization-server and openid-configuration with the issuer
// path inserted, then openid-configuration appended to the issuer path. A document counts only if
// it is a 200 JSON object with its required field (resource, issuer) set. Network errors are
// returned separately from "not found", so a timeout is never mistaken for missing metadata.

package probe

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/target"
)

type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

var resourceMetadataParam = regexp.MustCompile(`resource_metadata="([^"]+)"`)

func (p *prober) resourceMetadata(ctx context.Context, endpoint *url.URL, challenge *Exchange) (*ResourceMetadata, error) {
	var firstErr error
	for _, candidate := range resourceMetadataURLs(endpoint, challenge) {
		var md ResourceMetadata
		found, err := p.getJSON(ctx, candidate, &md)
		if found && md.Resource != "" {
			return &md, nil
		}
		firstErr = cmp.Or(firstErr, err)
	}
	return nil, firstErr
}

func (p *prober) authServerMetadata(ctx context.Context, resource *ResourceMetadata) (*AuthServerMetadata, error) {
	if resource == nil || len(resource.AuthorizationServers) == 0 {
		return nil, nil
	}
	issuer, err := url.Parse(resource.AuthorizationServers[0])
	if err != nil || issuer.Host == "" {
		return nil, nil
	}
	var firstErr error
	for _, candidate := range authServerMetadataURLs(issuer) {
		var md AuthServerMetadata
		found, err := p.getJSON(ctx, candidate, &md)
		if found && md.Issuer != "" {
			return &md, nil
		}
		firstErr = cmp.Or(firstErr, err)
	}
	return nil, firstErr
}

func resourceMetadataURLs(endpoint *url.URL, challenge *Exchange) []string {
	var urls []string
	if m := resourceMetadataParam.FindStringSubmatch(challenge.Header.Get("WWW-Authenticate")); m != nil && sameOrigin(endpoint, m[1]) {
		urls = append(urls, m[1])
	}
	root := origin(endpoint) + "/.well-known/oauth-protected-resource"
	if path := strings.TrimSuffix(endpoint.EscapedPath(), "/"); path != "" {
		urls = append(urls, root+path)
	}
	return append(urls, root)
}

func authServerMetadataURLs(issuer *url.URL) []string {
	base := origin(issuer)
	path := strings.TrimSuffix(issuer.EscapedPath(), "/")
	if path == "" {
		return []string{base + "/.well-known/oauth-authorization-server", base + "/.well-known/openid-configuration"}
	}
	return []string{
		base + "/.well-known/oauth-authorization-server" + path,
		base + "/.well-known/openid-configuration" + path,
		base + path + "/.well-known/openid-configuration",
	}
}

func origin(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

func sameOrigin(endpoint *url.URL, raw string) bool {
	t, err := target.ParseURL(raw)
	return err == nil && origin(t.URL) == origin(endpoint)
}

func (p *prober) getJSON(ctx context.Context, address string, v any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Accept", "application/json")
	ex, err := p.send(req)
	if err != nil {
		return false, err
	}
	if ex.Status != http.StatusOK || ex.Truncated {
		return false, nil
	}
	return json.Unmarshal(ex.Body, v) == nil, nil
}
