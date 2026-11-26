package cli

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name string
		raw  []string
		want http.Header
	}{
		{name: "none", raw: nil, want: http.Header{}},
		{name: "bearer token", raw: []string{"Authorization: Bearer abc"}, want: http.Header{"Authorization": {"Bearer abc"}}},
		{name: "canonicalizes name and trims", raw: []string{"  x-api-key :  k1 "}, want: http.Header{"X-Api-Key": {"k1"}}},
		{name: "value may contain colons", raw: []string{"X-Url: https://a:8080"}, want: http.Header{"X-Url": {"https://a:8080"}}},
		{name: "repeated name keeps both", raw: []string{"X-A: 1", "x-a: 2"}, want: http.Header{"X-A": {"1", "2"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeaders(tt.raw)

			if err != nil {
				t.Fatalf("parseHeaders error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseHeaders = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHeadersRejects(t *testing.T) {
	tests := []struct {
		name    string
		raw     []string
		wantErr string
	}{
		{name: "no colon", raw: []string{"Bearer s3cret"}, wantErr: `--header #1: want "Name: value"`},
		{name: "empty value", raw: []string{"Authorization:"}, wantErr: `want "Name: value"`},
		{name: "empty name", raw: []string{": s3cret"}, wantErr: `want "Name: value"`},
		{name: "space in name", raw: []string{"X Auth: s3cret"}, wantErr: "invalid header name"},
		{name: "line break in value", raw: []string{"X-A: s3cret\r\nHost: evil"}, wantErr: "line break"},
		{name: "reports position", raw: []string{"X-A: 1", "bad"}, wantErr: "--header #2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHeaders(tt.raw)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseHeaders error = %v, want it to contain %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Errorf("parseHeaders error leaks the header value: %v", err)
			}
		})
	}
}
