package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW004(t *testing.T) {
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "401 without metadata", ev: probe.Evidence{ToolsList: exchange(http.StatusUnauthorized), ResourceMetadataMissing: true}, want: "returned 401 but no protected resource metadata"},
		{name: "403 without metadata", ev: probe.Evidence{ToolsList: exchange(http.StatusForbidden), ResourceMetadataMissing: true}, want: "returned 403"},
		{name: "401 with metadata", ev: probe.Evidence{ToolsList: exchange(http.StatusUnauthorized), ResourceMetadata: &probe.ResourceMetadata{Resource: "r"}}},
		{name: "metadata lookup failed on the network", ev: probe.Evidence{ToolsList: exchange(http.StatusUnauthorized)}},
		{name: "open server is MW001, not MW004", ev: probe.Evidence{ToolsList: exchange(http.StatusOK), ResourceMetadataMissing: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW004").Evaluate(&tt.ev), tt.want)
		})
	}
}
