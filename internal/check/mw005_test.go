package check_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW005(t *testing.T) {
	withMethods := func(methods ...string) probe.Evidence {
		return probe.Evidence{AuthServerMetadata: &probe.AuthServerMetadata{Issuer: "i", CodeChallengeMethodsSupported: methods}}
	}
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "field absent", ev: withMethods(), want: "has no code_challenge_methods_supported"},
		{name: "plain only", ev: withMethods("plain"), want: "is [plain], without S256"},
		{name: "S256 advertised", ev: withMethods("plain", "S256")},
		{name: "metadata not found", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW005").Evaluate(&tt.ev), tt.want)
		})
	}
}
