// MW007 (critical): the server lists tools that change data to a client that sent no token, so
// anyone who reaches it can modify or delete what the tools manage. A tool counts as data-changing
// when its annotations say destructiveHint true or readOnlyHint false or, without a readOnlyHint,
// when the first word of its name is a write verb (create_issue, deleteFile, DROP_TABLE). The name
// heuristic is there because most servers ship no annotations; a tool that says readOnlyHint true
// is never flagged. Evidence names at most maxNamedTools tools so a large server does not flood the report.

package check

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

const maxNamedTools = 5

var writeVerbs = map[string]bool{
	"add": true, "apply": true, "approve": true, "ban": true, "cancel": true, "charge": true,
	"commit": true, "create": true, "delete": true, "deploy": true, "destroy": true, "disable": true,
	"drop": true, "edit": true, "enable": true, "exec": true, "execute": true, "grant": true,
	"insert": true, "install": true, "invite": true, "kill": true, "merge": true, "modify": true,
	"move": true, "patch": true, "pay": true, "post": true, "publish": true, "purge": true,
	"push": true, "put": true, "refund": true, "remove": true, "rename": true, "reset": true,
	"revoke": true, "send": true, "set": true, "terminate": true, "transfer": true, "truncate": true,
	"uninstall": true, "update": true, "upload": true, "write": true,
}

func mw007() Check {
	return Check{
		Rule: Rule{
			ID:       "MW007",
			Title:    "Data-changing tool without auth",
			Severity: SeverityCritical,
			OWASP:    owaspAuth,
			Remediation: "Require OAuth 2.1 bearer tokens before listing or calling tools, and give each " +
				"data-changing tool its own scope.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			if !ev.ToolsListed || !ev.ToolsList.Succeeded() {
				return nil
			}
			var changing []string
			for _, tool := range ev.Tools {
				if reason := changesData(tool); reason != "" {
					changing = append(changing, fmt.Sprintf("%s (%s)", tool.Name, reason))
				}
			}
			if len(changing) == 0 {
				return nil
			}
			return []string{"tools/list without a token lists data-changing tools: " + nameSome(changing)}
		},
	}
}

func changesData(tool probe.Tool) string {
	hints := probe.ToolAnnotations{}
	if tool.Annotations != nil {
		hints = *tool.Annotations
	}
	switch {
	case isTrue(hints.ReadOnlyHint):
		return ""
	case isTrue(hints.DestructiveHint):
		return "destructiveHint"
	case hints.ReadOnlyHint != nil:
		return "readOnlyHint false"
	case writeVerbs[firstWord(tool.Name)]:
		return "write-style name"
	default:
		return ""
	}
}

func isTrue(b *bool) bool {
	return b != nil && *b
}

func firstWord(name string) string {
	prevLower := false
	for i, r := range name {
		if !unicode.IsLetter(r) || (prevLower && unicode.IsUpper(r)) {
			return strings.ToLower(name[:i])
		}
		prevLower = unicode.IsLower(r)
	}
	return strings.ToLower(name)
}

func nameSome(items []string) string {
	if len(items) <= maxNamedTools {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:maxNamedTools], ", "), len(items)-maxNamedTools)
}
