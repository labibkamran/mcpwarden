// Package check holds the security rules (MW001–MW012) and the types they share.
// Checks judge collected evidence and perform no network I/O (FR-015). Severity is
// ordered low < medium < high < critical so thresholds such as --fail-on are plain
// comparisons; its zero value is invalid.
package check

import (
	"fmt"
	"strings"
)

type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

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
