// MW009 (high): a config file holds a secret in plain text, in an env value, a header or a
// command argument, so anyone who can read the file, its backups or the repository it is committed
// to can use the key. Values are matched against well-known key formats (AWS, GitHub, Anthropic,
// OpenAI, Slack, Stripe, Google, private keys, JWTs) and literal bearer tokens; ${...} references
// such as ${input:token} or ${env:TOKEN} are removed first because they point to a secret store.
// Evidence says where the secret is and what kind it is, never the value (FR-022).

package check

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

type keyFormat struct {
	kind    string
	pattern *regexp.Regexp
}

var (
	variableRef = regexp.MustCompile(`\$\{[^}]*\}`)
	keyFormats  = []keyFormat{
		{"an AWS access key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"a GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`)},
		{"an Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
		{"an OpenAI API key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{20,}`)},
		{"a Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
		{"a Stripe live key", regexp.MustCompile(`\b[rs]k_live_[A-Za-z0-9]{16,}`)},
		{"a Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
		{"a private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
		{"a JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
		{"a literal bearer token", regexp.MustCompile(`(?i)^\s*bearer\s+\S{8,}`)},
	}
)

func mw009() Check {
	return Check{
		Rule: Rule{
			ID:       "MW009",
			Title:    "Plaintext secret in config",
			Severity: SeverityHigh,
			OWASP:    owaspExposure,
			Remediation: "Remove the secret from the file, rotate it, and reference a secret store instead, " +
				"for example ${input:token} in VS Code or ${env:TOKEN}.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			srv := ev.Target.Server
			if srv == nil {
				return nil
			}
			places := slices.Concat(
				secretsIn("env", srv.Env),
				secretsIn("header", srv.Headers),
				secretsInArgs(srv.Args),
			)
			if len(places) == 0 {
				return nil
			}
			return []string{"config stores secrets in plain text: " + nameSome(places)}
		},
	}
}

func secretsIn(field string, values map[string]string) []string {
	var places []string
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if kind := keyKind(values[name]); kind != "" {
			places = append(places, fmt.Sprintf("%s %s holds %s", field, name, kind))
		}
	}
	return places
}

func secretsInArgs(args []string) []string {
	var places []string
	for i, arg := range args {
		if kind := keyKind(arg); kind != "" {
			places = append(places, fmt.Sprintf("argument %d holds %s", i+1, kind))
		}
	}
	return places
}

func keyKind(value string) string {
	literal := variableRef.ReplaceAllString(value, "")
	for _, f := range keyFormats {
		if f.pattern.MatchString(literal) {
			return f.kind
		}
	}
	return ""
}
