// Rule selection (FR-018): rule IDs turned on or off, uppercased and deduplicated.
// A rule both enabled and disabled is an error. Only the MWnnn syntax is checked
// until the rule registry exists (M2).

package check

import (
	"fmt"
	"slices"
	"strings"
)

type RuleSelection struct {
	Enable  []string
	Disable []string
}

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
