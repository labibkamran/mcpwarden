// --header parsing: "Name: value" pairs become an http.Header. Names must be
// RFC 9110 tokens and values may not contain CR, LF or NUL. Errors cite the flag
// by position and never include the value, which usually holds a token (FR-022).

package cli

import (
	"fmt"
	"net/http"
	"strings"
)

func parseHeaders(raw []string) (http.Header, error) {
	headers := http.Header{}
	for i, line := range raw {
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch {
		case !ok || name == "" || value == "":
			return nil, fmt.Errorf(`--header #%d: want "Name: value"`, i+1)
		case !isToken(name):
			return nil, fmt.Errorf("--header #%d: invalid header name", i+1)
		case strings.ContainsAny(value, "\r\n\x00"):
			return nil, fmt.Errorf("--header #%d: value contains a line break or NUL", i+1)
		}
		headers.Add(name, value)
	}
	return headers, nil
}

func isToken(s string) bool {
	for _, c := range []byte(s) {
		isAlnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !isAlnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			return false
		}
	}
	return s != ""
}
