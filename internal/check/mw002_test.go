package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW002(t *testing.T) {
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "foreign origin accepted", ev: probe.Evidence{ForeignOrigin: exchange(http.StatusOK)}, want: "Origin: https://evil.example returned 200 instead of 403"},
		{name: "foreign origin rejected", ev: probe.Evidence{ForeignOrigin: exchange(http.StatusForbidden)}},
		{name: "auth check answered first", ev: probe.Evidence{ForeignOrigin: exchange(http.StatusUnauthorized)}},
		{name: "probe failed", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW002").Evaluate(&tt.ev), tt.want)
		})
	}
}
