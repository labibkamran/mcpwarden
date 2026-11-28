package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW003(t *testing.T) {
	const acao = "Access-Control-Allow-Origin"
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "wildcard", ev: probe.Evidence{Preflight: exchange(http.StatusNoContent, acao, "*")}, want: "Access-Control-Allow-Origin: *"},
		{name: "echoed foreign origin", ev: probe.Evidence{Preflight: exchange(http.StatusNoContent, acao, probe.ForeignOrigin)}, want: "echoed Origin https://evil.example"},
		{name: "known origin only", ev: probe.Evidence{Preflight: exchange(http.StatusNoContent, acao, "https://app.example")}},
		{name: "no cors headers", ev: probe.Evidence{Preflight: exchange(http.StatusMethodNotAllowed)}},
		{name: "probe failed", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW003").Evaluate(&tt.ev), tt.want)
		})
	}
}
