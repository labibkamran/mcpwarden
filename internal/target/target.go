// Package target turns user input into scan targets. ParseURL accepts only http
// and https (FR-005) and normalizes: scheme and host lowercased, default port and
// fragment removed, empty path becomes "/". Whitespace inside the URL is rejected, because
// net/url keeps a raw space in the query and the result would not parse back to itself
// (RFC 3986 requires %20). URLs with credentials are rejected and
// parse errors drop the raw input (url.Error repeats it), so secrets never reach
// output (FR-022). A target from a config file also carries its Server entry (config.go); its URL
// is nil when the entry runs a local command or its url cannot be parsed.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

type Target struct {
	URL    *url.URL
	Server *Server
}

func (t Target) String() string {
	switch {
	case t.Server == nil:
		return t.URL.String()
	case t.URL != nil:
		return fmt.Sprintf("%s: %s (%s)", t.Server.ConfigPath, t.Server.Name, t.URL)
	default:
		return fmt.Sprintf("%s: %s", t.Server.ConfigPath, t.Server.Name)
	}
}

func ParseURL(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return Target{}, errors.New("invalid url: contains whitespace: percent-encode it as %20")
	}
	u, err := url.Parse(raw)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
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
	if isIPv6 := strings.Contains(host, ":"); isIPv6 {
		return "[" + host + "]"
	}
	return host
}
