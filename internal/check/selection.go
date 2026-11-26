package check

import (
	"fmt"
	"slices"
	"strings"
)

// RuleSelection holds the rule IDs a user turned on or off (FR-018),
// uppercased and without duplicates.
type RuleSelection struct {
	Enable  []string
	Disable []string
}

// ParseRuleSelection validates the enabled and disabled rule IDs. IDs are
// case-insensitive; a rule that is both enabled and disabled is an error.
func ParseRuleSelection(enable, disable []string) (RuleSelection, error) {
	on, err := parseRuleIDs(enable)
	if err != nil {
		return RuleSelection{}, err
	}
	off, err := parseRuleIDs(disable)
	if err != nil {
		return RuleSelection{}, err
	}
	for _, id := range on {
		if slices.Contains(off, id) {
			return RuleSelection{}, fmt.Errorf("rule %s is both enabled and disabled", id)
		}
	}
	return RuleSelection{Enable: on, Disable: off}, nil
}

func parseRuleIDs(raw []string) ([]string, error) {
	var ids []string
	for _, r := range raw {
		id := strings.ToUpper(strings.TrimSpace(r))
		if !isRuleID(id) {
			return nil, fmt.Errorf("invalid rule ID %q: want the form MW001", r)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// isRuleID reports whether id has the MWnnn form.
// ponytail: syntax only; check IDs against the rule registry once it exists (M2).
func isRuleID(id string) bool {
	if len(id) != len("MW000") || !strings.HasPrefix(id, "MW") {
		return false
	}
	for _, c := range id[2:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
