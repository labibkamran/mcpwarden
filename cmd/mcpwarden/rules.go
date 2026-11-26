package main

import (
	"fmt"
	"slices"
	"strings"
)

// ruleSelection holds the rule IDs turned on or off with --enable and
// --disable (FR-018), uppercased and without duplicates.
type ruleSelection struct {
	enable  []string
	disable []string
}

func parseRuleSelection(enable, disable []string) (ruleSelection, error) {
	on, err := parseRuleIDs("--enable", enable)
	if err != nil {
		return ruleSelection{}, err
	}
	off, err := parseRuleIDs("--disable", disable)
	if err != nil {
		return ruleSelection{}, err
	}
	for _, id := range on {
		if slices.Contains(off, id) {
			return ruleSelection{}, fmt.Errorf("rule %s is both enabled and disabled", id)
		}
	}
	return ruleSelection{enable: on, disable: off}, nil
}

func parseRuleIDs(flagName string, raw []string) ([]string, error) {
	var ids []string
	for _, r := range raw {
		id := strings.ToUpper(strings.TrimSpace(r))
		if !isRuleID(id) {
			return nil, fmt.Errorf("%s %q: want a rule ID such as MW001", flagName, r)
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
