// Package target turns user input into scan targets.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is one thing to scan. For now that is a remote MCP server URL;
// config-file server entries arrive with the config parser (FR-006).
type Target struct {
	URL *url.URL
}

// String returns the normalized target URL.
func (t Target) String() string {
	return t.URL.String()
}

// ParseURL validates raw as an http or https server URL and normalizes it
// (FR-005): the scheme and host are lowercased, a default port and the
// fragment are removed, and an empty path becomes "/". URLs that carry
// credentials are rejected so secrets never reach reports (FR-022).
func ParseURL(raw string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			// url.Error repeats the raw input, which may hold credentials.
			err = urlErr.Err
		}
		return Target{}, fmt.Errorf("invalid url: %w", err)
	}
	if err := validate(u); err != nil {
		return Target{}, err
	}

	u.Host = normalizeHost(u.Scheme, u.Hostname(), u.Port())
	u.Fragment, u.RawFragment = "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return Target{URL: u}, nil
}

func validate(u *url.URL) error {
	switch {
	case u.Scheme == "":
		return errors.New("missing scheme: want http:// or https://")
	case u.Scheme != "http" && u.Scheme != "https":
		return fmt.Errorf("unsupported scheme %q: want http or https", u.Scheme)
	case u.User != nil:
		return errors.New("credentials in the url are not allowed: pass them with --header")
	case u.Hostname() == "":
		return errors.New("missing host")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port %q: want 1-65535", port)
		}
	}
	return nil
}

func normalizeHost(scheme, host, port string) string {
	host = strings.ToLower(host)
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") { // IPv6 literal
		return "[" + host + "]"
	}
	return host
}
