// Package score turns findings into a grade and the --fail-on decision (FR-019, FR-021). A
// target starts at 100 points and each finding costs points by severity: critical 40, high 20,
// medium 10, low 5. The grade is A at 100 (no findings), B from 90, C from 75, D from 60, F below.
// One critical finding alone gives D, matching the report example in SRS 5.3, and findings add up,
// so two critical findings give F. Fails reports whether any finding is at or above the threshold.
package score

import "github.com/labibkamran/mcpwarden/internal/check"

func Grade(findings []check.Finding) string {
	points := 100
	for _, f := range findings {
		points -= cost(f.Rule.Severity)
	}
	switch {
	case points == 100:
		return "A"
	case points >= 90:
		return "B"
	case points >= 75:
		return "C"
	case points >= 60:
		return "D"
	default:
		return "F"
	}
}

func cost(s check.Severity) int {
	switch s {
	case check.SeverityCritical:
		return 40
	case check.SeverityHigh:
		return 20
	case check.SeverityMedium:
		return 10
	default:
		return 5
	}
}

func Fails(findings []check.Finding, failOn check.Severity) bool {
	for _, f := range findings {
		if f.Rule.Severity >= failOn {
			return true
		}
	}
	return false
}
