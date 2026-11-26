package check_test

import (
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    check.Severity
		wantErr bool
	}{
		{name: "low", input: "low", want: check.SeverityLow},
		{name: "medium", input: "medium", want: check.SeverityMedium},
		{name: "high", input: "high", want: check.SeverityHigh},
		{name: "critical", input: "critical", want: check.SeverityCritical},
		{name: "case insensitive", input: "HiGh", want: check.SeverityHigh},
		{name: "trims space", input: " critical ", want: check.SeverityCritical},
		{name: "unknown name", input: "severe", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := check.ParseSeverity(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("check.ParseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("check.ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityStringRoundTrips(t *testing.T) {
	for _, s := range []check.Severity{check.SeverityLow, check.SeverityMedium, check.SeverityHigh, check.SeverityCritical} {
		got, err := check.ParseSeverity(s.String())

		if err != nil || got != s {
			t.Errorf("check.ParseSeverity(%q) = %v, %v; want %v", s.String(), got, err, s)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if check.SeverityLow >= check.SeverityMedium || check.SeverityMedium >= check.SeverityHigh || check.SeverityHigh >= check.SeverityCritical {
		t.Error("severities must order low < medium < high < critical for --fail-on comparisons")
	}
}

func TestSeverityStringInvalid(t *testing.T) {
	if got := check.Severity(0).String(); got != "Severity(0)" {
		t.Errorf("check.Severity(0).String() = %q, want %q", got, "Severity(0)")
	}
}
