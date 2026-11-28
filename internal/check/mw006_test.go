package check_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW006(t *testing.T) {
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "iss parameter not supported", ev: probe.Evidence{AuthServerMetadata: &probe.AuthServerMetadata{Issuer: "i"}},
			want: "does not set authorization_response_iss_parameter_supported"},
		{name: "iss parameter supported", ev: probe.Evidence{AuthServerMetadata: &probe.AuthServerMetadata{IssParameterSupported: true}}},
		{name: "metadata not found", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW006").Evaluate(&tt.ev), tt.want)
		})
	}
}
