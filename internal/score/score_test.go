package score_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/score"
)

func findings(severities ...check.Severity) []check.Finding {
	var fs []check.Finding
	for _, s := range severities {
		fs = append(fs, check.Finding{Rule: check.Rule{Severity: s}})
	}
	return fs
}

const (
	low      = check.SeverityLow
	medium   = check.SeverityMedium
	high     = check.SeverityHigh
	critical = check.SeverityCritical
)

func TestGrade(t *testing.T) {
	tests := []struct {
		name     string
		findings []check.Finding
		want     string
	}{
		{name: "no findings", want: "A"},
		{name: "one low", findings: findings(low), want: "B"},
		{name: "one medium", findings: findings(medium), want: "B"},
		{name: "one high", findings: findings(high), want: "C"},
		{name: "two mediums", findings: findings(medium, medium), want: "C"},
		{name: "one critical", findings: findings(critical), want: "D"},
		{name: "two highs", findings: findings(high, high), want: "D"},
		{name: "critical and high", findings: findings(critical, high), want: "F"},
		{name: "two criticals", findings: findings(critical, critical), want: "F"},
		{name: "points never go below F", findings: findings(critical, critical, critical, critical), want: "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := score.Grade(tt.findings); got != tt.want {
				t.Errorf("Grade = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFails(t *testing.T) {
	tests := []struct {
		name     string
		findings []check.Finding
		failOn   check.Severity
		want     bool
	}{
		{name: "no findings pass", failOn: low, want: false},
		{name: "finding at the threshold fails", findings: findings(high), failOn: high, want: true},
		{name: "finding above the threshold fails", findings: findings(critical), failOn: high, want: true},
		{name: "finding below the threshold passes", findings: findings(medium), failOn: high, want: false},
		{name: "fail-on low catches everything", findings: findings(low), failOn: low, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := score.Fails(tt.findings, tt.failOn); got != tt.want {
				t.Errorf("Fails = %v, want %v", got, tt.want)
			}
		})
	}
}
