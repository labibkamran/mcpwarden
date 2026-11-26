// Package check holds the security rules (MW001–MW012) and the types they
// share. Checks judge collected evidence and perform no network I/O (FR-015).
package check

import (
	"fmt"
	"strings"
)

// Severity ranks how serious a finding is. Higher values are more severe,
// so severities compare with < and >. The zero value is not a valid severity.
type Severity int

// Severity levels, from least to most severe (Appendix A).
const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity converts a case-insensitive name such as "high" to a Severity.
func ParseSeverity(name string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("unknown severity %q: want low, medium, high or critical", name)
	}
}

// String returns the lowercase name used in flags and reports.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return fmt.Sprintf("Severity(%d)", int(s))
	}
}
