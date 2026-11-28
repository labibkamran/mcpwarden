// MW008 (high): a config entry starts its server through a command that runs arbitrary code
// rather than a pinned package: a shell given a script (sh -c, cmd /c, powershell -Command), a
// download piped into a shell (curl ... | sh), or inline interpreter code (python -c, node -e).
// Whoever can edit that string, or the URL it downloads, controls the user's machine. Judged on
// the config text only: commands are never run (SRS 2.4). Evidence names the program and flag,
// never the arguments, because they often hold tokens (FR-022). Windows paths and .exe are handled
// so C:\Windows\System32\cmd.exe counts as cmd.

package check

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/labibkamran/mcpwarden/internal/probe"
)

var (
	shells         = []string{"sh", "bash", "zsh", "dash", "ksh", "fish"}
	powershells    = []string{"powershell", "pwsh"}
	scriptFlagsPS  = []string{"-c", "-command", "-e", "-ec", "-enc", "-encodedcommand"}
	inlineCodeFlag = map[string][]string{
		"python": {"-c"}, "py": {"-c"}, "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval"},
		"perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "bun": {"-e", "--eval"}, "deno": {"eval"},
	}
	pipeToShell = regexp.MustCompile(`\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`)
)

func mw008() Check {
	return Check{
		Rule: Rule{
			ID:       "MW008",
			Title:    "Dangerous STDIO command",
			Severity: SeverityHigh,
			OWASP:    owaspCommand,
			Remediation: "Start the server from a pinned package or a fixed binary path, without a shell, " +
				"a piped download or inline interpreter code.",
		},
		Evaluate: func(ev *probe.Evidence) []string {
			srv := ev.Target.Server
			if srv == nil || srv.Command == "" {
				return nil
			}
			if reason := dangerousCommand(programName(srv.Command), srv.Command, srv.Args); reason != "" {
				return []string{"config command " + reason}
			}
			return nil
		},
	}
}

func dangerousCommand(program, command string, args []string) string {
	if m := pipeToShell.FindStringSubmatch(strings.Join(append([]string{command}, args...), " ")); m != nil {
		return fmt.Sprintf("pipes a %s download into a shell", m[1])
	}
	switch {
	case slices.Contains(shells, program) && slices.ContainsFunc(args, isShellScriptFlag):
		return fmt.Sprintf("runs %s -c with a script", program)
	case program == "cmd" && slices.ContainsFunc(args, func(a string) bool { return equalsAny(a, "/c", "/k") }):
		return "runs cmd /c with a script"
	case slices.Contains(powershells, program) && slices.ContainsFunc(args, func(a string) bool { return equalsAny(a, scriptFlagsPS...) }):
		return fmt.Sprintf("runs %s -Command with a script", program)
	}
	for interpreter, flags := range inlineCodeFlag {
		if isInterpreter(program, interpreter) && slices.ContainsFunc(args, func(a string) bool { return slices.Contains(flags, a) }) {
			return fmt.Sprintf("runs inline %s code", interpreter)
		}
	}
	return ""
}

func programName(command string) string {
	name := command[strings.LastIndexAny(command, `/\`)+1:]
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

func isShellScriptFlag(arg string) bool {
	return len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg, "c")
}

func isInterpreter(program, interpreter string) bool {
	version := strings.TrimPrefix(program, interpreter)
	return len(version) < len(program) && strings.Trim(version, "0123456789.") == ""
}

func equalsAny(arg string, options ...string) bool {
	return slices.ContainsFunc(options, func(o string) bool { return strings.EqualFold(arg, o) })
}
