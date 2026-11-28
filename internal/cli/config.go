// --config (FR-006): the MCP client config file is read with a 1 MB cap, like a probe response
// (FR-012), and its servers are scanned after the URL arguments. The file is only read: commands
// in it are never run (SRS 2.4).

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/labibkamran/mcpwarden/internal/target"
)

const maxConfigBytes = 1 << 20

func scanTargets(opts ScanOptions) ([]target.Target, error) {
	if opts.ConfigPath == "" {
		return opts.Targets, nil
	}
	data, err := readConfig(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	}
	fromConfig, err := target.ParseConfig(opts.ConfigPath, data)
	if err != nil {
		return nil, fmt.Errorf("--config %s: %w", opts.ConfigPath, err)
	}
	return slices.Concat(opts.Targets, fromConfig), nil
}

func readConfig(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%s is larger than 1 MB", path)
	}
	return data, nil
}
