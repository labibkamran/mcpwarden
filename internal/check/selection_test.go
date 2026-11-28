package check_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/check"
)

func TestParseRuleSelection(t *testing.T) {
	tests := []struct {
		name    string
		enable  []string
		disable []string
		want    check.RuleSelection
	}{
		{name: "none", want: check.RuleSelection{}},
		{name: "enable and disable", enable: []string{"MW001"}, disable: []string{"MW003"}, want: check.RuleSelection{Enable: []string{"MW001"}, Disable: []string{"MW003"}}},
		{name: "uppercases", disable: []string{"mw003"}, want: check.RuleSelection{Disable: []string{"MW003"}}},
		{name: "drops duplicates", disable: []string{"MW003", "mw003", "MW004"}, want: check.RuleSelection{Disable: []string{"MW003", "MW004"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := check.ParseRuleSelection(tt.enable, tt.disable)

			if err != nil {
				t.Fatalf("ParseRuleSelection error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRuleSelection = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseRuleSelectionRejects(t *testing.T) {
	tests := []struct {
		name    string
		enable  []string
		disable []string
		wantErr string
	}{
		{name: "wrong prefix", disable: []string{"XX003"}, wantErr: `unknown rule ID "XX003"`},
		{name: "too short", enable: []string{"MW1"}, wantErr: `unknown rule ID "MW1"`},
		{name: "well-formed but not in the catalog", enable: []string{"MW999"}, wantErr: "run mcpwarden list-checks"},
		{name: "empty", disable: []string{""}, wantErr: "unknown rule ID"},
		{name: "conflict", enable: []string{"MW003"}, disable: []string{"mw003"}, wantErr: "MW003 is both enabled and disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := check.ParseRuleSelection(tt.enable, tt.disable)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParseRuleSelection error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
