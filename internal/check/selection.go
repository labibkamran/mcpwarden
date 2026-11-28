// Rule selection (FR-018): rule IDs turned on or off, uppercased and deduplicated. An ID must name
// a rule in the Catalog, and a rule both enabled and disabled is an error.

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
		if !isKnownRule(id) {
			return nil, fmt.Errorf("unknown rule ID %q: run mcpwarden list-checks for the rules", r)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func isKnownRule(id string) bool {
	return slices.ContainsFunc(Catalog(), func(c Check) bool { return c.ID == id })
}
