package cli_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/cli"
)

func TestScanHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    http.Header
	}{
		{name: "none", headers: nil, want: http.Header{}},
		{name: "bearer token", headers: []string{"Authorization: Bearer abc"}, want: http.Header{"Authorization": {"Bearer abc"}}},
		{name: "canonicalizes name and trims", headers: []string{"  x-api-key :  k1 "}, want: http.Header{"X-Api-Key": {"k1"}}},
		{name: "value may contain colons", headers: []string{"X-Url: https://a:8080"}, want: http.Header{"X-Url": {"https://a:8080"}}},
		{name: "repeated name keeps both", headers: []string{"X-A: 1", "x-a: 2"}, want: http.Header{"X-A": {"1", "2"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := cli.ParseScanArgs(withHeaders("https://a", tt.headers))

			if err != nil {
				t.Fatalf("ParseScanArgs error: %v", err)
			}
			if !reflect.DeepEqual(opts.Headers, tt.want) {
				t.Errorf("Headers = %v, want %v", opts.Headers, tt.want)
			}
		})
	}
}

func TestScanHeadersRejects(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		wantErr string
	}{
		{name: "no colon", headers: []string{"Bearer s3cret"}, wantErr: `--header #1: want "Name: value"`},
		{name: "empty value", headers: []string{"Authorization:"}, wantErr: `want "Name: value"`},
		{name: "empty name", headers: []string{": s3cret"}, wantErr: `want "Name: value"`},
		{name: "space in name", headers: []string{"X Auth: s3cret"}, wantErr: "invalid header name"},
		{name: "line break in value", headers: []string{"X-A: s3cret\r\nHost: evil"}, wantErr: "line break"},
		{name: "reports position", headers: []string{"X-A: 1", "bad"}, wantErr: "--header #2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cli.ParseScanArgs(withHeaders("https://a", tt.headers))

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ParseScanArgs error = %v, want it to contain %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("error leaks the header value: %v", err)
			}
		})
	}
}

func withHeaders(url string, headers []string) []string {
	args := []string{url}
	for _, h := range headers {
		args = append(args, "--header", h)
	}
	return args
}
