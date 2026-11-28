package check_test

import (
	"net/http"
	"testing"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

func TestMW007(t *testing.T) {
	yes, no := true, false
	listed := func(status int, tools ...probe.Tool) probe.Evidence {
		return probe.Evidence{ToolsList: exchange(status), ToolsListed: true, Tools: tools}
	}
	named := func(names ...string) []probe.Tool {
		var tools []probe.Tool
		for _, n := range names {
			tools = append(tools, probe.Tool{Name: n})
		}
		return tools
	}
	tests := []struct {
		name string
		ev   probe.Evidence
		want string
	}{
		{name: "destructive hint", ev: listed(http.StatusOK, probe.Tool{Name: "wipe", Annotations: &probe.ToolAnnotations{DestructiveHint: &yes}}),
			want: "data-changing tools: wipe (destructiveHint)"},
		{name: "read-only hint false", ev: listed(http.StatusOK, probe.Tool{Name: "tag", Annotations: &probe.ToolAnnotations{ReadOnlyHint: &no}}),
			want: "tag (readOnlyHint false)"},
		{name: "read-only hint wins over a write-style name", ev: listed(http.StatusOK, probe.Tool{Name: "delete_preview", Annotations: &probe.ToolAnnotations{ReadOnlyHint: &yes}})},
		{name: "snake case verb", ev: listed(http.StatusOK, named("create_issue")...), want: "create_issue (write-style name)"},
		{name: "camel case verb", ev: listed(http.StatusOK, named("deleteFile")...), want: "deleteFile (write-style name)"},
		{name: "upper case verb", ev: listed(http.StatusOK, named("DROP_TABLE")...), want: "DROP_TABLE (write-style name)"},
		{name: "verb only as a later word", ev: listed(http.StatusOK, named("get_deleted_items", "search")...)},
		{name: "names capped", ev: listed(http.StatusOK, named("add_a", "add_b", "add_c", "add_d", "add_e", "add_f", "add_g")...),
			want: "add_e (write-style name) and 2 more"},
		{name: "server demands a token", ev: listed(http.StatusUnauthorized, named("delete_all")...)},
		{name: "nothing listed", ev: probe.Evidence{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSummary(t, catalogCheck(t, "MW007").Evaluate(&tt.ev), tt.want)
		})
	}
}
