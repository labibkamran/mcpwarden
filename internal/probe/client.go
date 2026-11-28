// Hardened HTTP client for probes (FR-011, FR-012). A guard in the transport refuses every
// request except GET, OPTIONS and a POST whose Mcp-Method is tools/list, so no bug elsewhere can
// send a state-changing request. Each request has a timeout. A redirect is followed only when it
// keeps the scheme and host, at most 3 times; otherwise the redirect response itself is recorded.
// Bodies are read up to 1 MB and anything longer is cut off and marked Truncated.

package probe

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxBodyBytes   = 1 << 20
	maxRedirects   = 3
	readOnlyMethod = "tools/list"
)

var errNotReadOnly = errors.New("refused a request that is not read-only")

type Exchange struct {
	Status    int
	Header    http.Header
	Body      []byte
	Truncated bool
}

type readOnlyTransport struct {
	next http.RoundTripper
}

func (t readOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !isReadOnly(req) {
		return nil, fmt.Errorf("%w: %s %s", errNotReadOnly, req.Method, req.Header.Get("Mcp-Method"))
	}
	return t.next.RoundTrip(req)
}

func isReadOnly(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodOptions:
		return true
	case http.MethodPost:
		return req.Header.Get("Mcp-Method") == readOnlyMethod
	default:
		return false
	}
}

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     readOnlyTransport{next: http.DefaultTransport.(*http.Transport).Clone()},
		CheckRedirect: followSameHost,
	}
}

func followSameHost(req *http.Request, via []*http.Request) error {
	first := via[0].URL
	if len(via) > maxRedirects || req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return http.ErrUseLastResponse
	}
	return nil
}

func send(client *http.Client, req *http.Request) (*Exchange, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	ex := &Exchange{Status: resp.StatusCode, Header: resp.Header, Body: body}
	if len(body) > maxBodyBytes {
		ex.Body, ex.Truncated = body[:maxBodyBytes], true
	}
	return ex, nil
}

func (ex *Exchange) Succeeded() bool {
	return ex != nil && ex.Status >= 200 && ex.Status < 300
}
