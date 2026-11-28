// MCP client config files (FR-006). ParseConfig reads the mcpServers map of Claude Desktop,
// Cursor and Claude Code, and the servers map of VS Code (mcp.json, or mcp.servers in
// settings.json), and returns one Target per server entry, sorted by name so reports are stable.
// STDIO commands are kept as text and never executed (SRS 2.4). An entry whose url is not a plain
// http(s) URL, for example one built from a ${...} variable, keeps URL nil: its config is still
// checked but nothing is probed. VS Code allows comments and trailing commas, so they are blanked
// out first, keeping byte offsets, which lets syntax errors report the right line. Errors name the
// server, never a value, because env and headers often hold secrets (FR-022).

package target

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
)

type Server struct {
	ConfigPath string
	Name       string
	Command    string
	Args       []string
	Env        map[string]string
	URL        string
	Headers    map[string]string
}

type rawServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]any    `json:"env"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type rawConfig struct {
	MCPServers map[string]rawServer `json:"mcpServers"`
	Servers    map[string]rawServer `json:"servers"`
	MCP        struct {
		Servers map[string]rawServer `json:"servers"`
	} `json:"mcp"`
}

func ParseConfig(path string, data []byte) ([]Target, error) {
	clean := stripJSONC(data)
	var cfg rawConfig
	if err := json.Unmarshal(clean, &cfg); err != nil {
		return nil, describeJSONError(clean, err)
	}
	entries := mergeServers(cfg.MCPServers, cfg.Servers, cfg.MCP.Servers)
	if len(entries) == 0 {
		return nil, errors.New(`no MCP servers found: want "mcpServers" (Claude Desktop, Cursor) or "servers" (VS Code)`)
	}

	targets := make([]Target, 0, len(entries))
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		t, err := newConfigTarget(path, name, entries[name])
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func mergeServers(groups ...map[string]rawServer) map[string]rawServer {
	all := map[string]rawServer{}
	for _, m := range groups {
		for name, s := range m {
			all[name] = s
		}
	}
	return all
}

func newConfigTarget(path, name string, raw rawServer) (Target, error) {
	if raw.Command == "" && raw.URL == "" {
		return Target{}, fmt.Errorf(`server %q: want "command" or "url"`, name)
	}
	srv := &Server{
		ConfigPath: path,
		Name:       name,
		Command:    raw.Command,
		Args:       raw.Args,
		Env:        envStrings(raw.Env),
		URL:        raw.URL,
		Headers:    raw.Headers,
	}
	t := Target{Server: srv}
	if parsed, err := ParseURL(raw.URL); raw.URL != "" && err == nil {
		t.URL = parsed.URL
	}
	return t, nil
}

func envStrings(env map[string]any) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		if v != nil {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

func describeJSONError(data []byte, err error) error {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		line := 1 + bytes.Count(data[:syntaxErr.Offset], []byte("\n"))
		return fmt.Errorf("invalid JSON on line %d: %w", line, err)
	}
	return fmt.Errorf("unexpected config shape: %w", err)
}
