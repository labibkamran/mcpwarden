package check_test

import (
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/target"
)

func fakeKey(prefix string, n int) string {
	return prefix + strings.Repeat("a1B2", n/4+1)[:n]
}

func withServer(srv target.Server) probe.Evidence {
	return probe.Evidence{Target: target.Target{Server: &srv}}
}

func TestMW009(t *testing.T) {
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "aws key in env", ev: withServer(target.Server{Env: map[string]string{"AWS_KEY": "AKIA" + "IOSFODNN7EXAMPLE"}}), want: "env AWS_KEY holds an AWS access key"},
		{name: "github token", ev: withServer(target.Server{Env: map[string]string{"GH": fakeKey("ghp_", 36)}}), want: "env GH holds a GitHub token"},
		{name: "anthropic key is not called openai", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("sk-ant-", 30)}}), want: "holds an Anthropic API key"},
		{name: "openai project key", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("sk-proj-", 30)}}), want: "holds an OpenAI API key"},
		{name: "slack token", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("xoxb-", 20)}}), want: "holds a Slack token"},
		{name: "stripe live key", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("sk_live_", 24)}}), want: "holds a Stripe live key"},
		{name: "google key", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("AIza", 35)}}), want: "holds a Google API key"},
		{name: "private key", ev: withServer(target.Server{Env: map[string]string{"K": "-----BEGIN " + "RSA PRIVATE KEY-----\nMII"}}), want: "holds a private key"},
		{name: "jwt", ev: withServer(target.Server{Env: map[string]string{"K": fakeKey("eyJ", 12) + "." + fakeKey("eyJ", 12) + "." + fakeKey("", 12)}}), want: "holds a JWT"},
		{name: "literal bearer header", ev: withServer(target.Server{Headers: map[string]string{"Authorization": "Bearer " + fakeKey("", 24)}}), want: "header Authorization holds a literal bearer token"},
		{name: "key in an argument", ev: withServer(target.Server{Args: []string{"--api-key", fakeKey("sk-", 40)}}), want: "argument 2 holds an OpenAI API key"},
		{name: "several places sorted", ev: withServer(target.Server{Env: map[string]string{"B": fakeKey("ghp_", 36), "A": fakeKey("ghp_", 36)}}),
			want: "env A holds a GitHub token, env B holds a GitHub token"},
		{name: "bearer from an input variable", ev: withServer(target.Server{Headers: map[string]string{"Authorization": "Bearer ${input:token}"}})},
		{name: "env reference", ev: withServer(target.Server{Env: map[string]string{"GH": "${env:GITHUB_TOKEN}"}})},
		{name: "ordinary values", ev: withServer(target.Server{Env: map[string]string{"PORT": "8080", "MODE": "skip-tests"}, Args: []string{"-y", "pkg@1.0.0"}})},
		{name: "not a config target", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW009").Evaluate(&tt.ev), tt.want)
		})
	}
}

func TestMW009NeverQuotesTheSecret(t *testing.T) {
	secret := fakeKey("ghp_", 36)
	ev := withServer(target.Server{Env: map[string]string{"GH": secret}})

	got := catalogCheck(t, "MW009").Evaluate(&ev)

	if len(got) != 1 || strings.Contains(got[0], secret) || strings.Contains(got[0], secret[4:12]) {
		t.Errorf("findings = %q, want one that does not contain the secret", got)
	}
}
