package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRuleSelection(t *testing.T) {
	tests := []struct {
		name    string
		enable  []string
		disable []string
		want    ruleSelection
	}{
		{name: "none", want: ruleSelection{}},
		{name: "enable and disable", enable: []string{"MW011"}, disable: []string{"MW003"}, want: ruleSelection{enable: []string{"MW011"}, disable: []string{"MW003"}}},
		{name: "uppercases", disable: []string{"mw003"}, want: ruleSelection{disable: []string{"MW003"}}},
		{name: "drops duplicates", disable: []string{"MW003", "mw003", "MW004"}, want: ruleSelection{disable: []string{"MW003", "MW004"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRuleSelection(tt.enable, tt.disable)

			if err != nil {
				t.Fatalf("parseRuleSelection error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRuleSelection = %+v, want %+v", got, tt.want)
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
		{name: "wrong prefix", disable: []string{"XX003"}, wantErr: `--disable "XX003"`},
		{name: "too short", enable: []string{"MW1"}, wantErr: `--enable "MW1"`},
		{name: "letters in number", enable: []string{"MW0A1"}, wantErr: "want a rule ID"},
		{name: "empty", disable: []string{""}, wantErr: "want a rule ID"},
		{name: "conflict", enable: []string{"MW003"}, disable: []string{"mw003"}, wantErr: "MW003 is both enabled and disabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRuleSelection(tt.enable, tt.disable)

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseRuleSelection error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}
