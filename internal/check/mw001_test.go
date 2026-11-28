package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW001(t *testing.T) {
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "tools listed without a token", ev: probe.Evidence{ToolsList: exchange(http.StatusOK), ToolsListed: true, Tools: []probe.Tool{{Name: "a"}, {Name: "b"}}}, want: "returned 200 with 2 tools and no token"},
		{name: "empty tool list is still open", ev: probe.Evidence{ToolsList: exchange(http.StatusOK), ToolsListed: true}, want: "with 0 tools"},
		{name: "401 is protected", ev: probe.Evidence{ToolsList: exchange(http.StatusUnauthorized)}},
		{name: "200 without a json-rpc result", ev: probe.Evidence{ToolsList: exchange(http.StatusOK)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW001").Evaluate(&tt.ev), tt.want)
		})
	}
}
