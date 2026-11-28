// The scan command (FR-002, FR-014, FR-021): parse the options, scan every target with the
// selected rules and write the report to stdout or --output. Exit codes: 1 when any finding is at
// or above --fail-on; otherwise 2 when a target was unreachable, because its result is missing;
// otherwise 0. Usage errors exit 2 with a pointer to -h (FR-004), and Ctrl-C cancels the scan.
// --config targets (milestone 3) and json or sarif output (milestone 4) are refused until they
// exist. The report file gets mode 0600 because it lists the target's weaknesses.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/engine"
	"github.com/labibkamran/mcpwarden/internal/probe"
	"github.com/labibkamran/mcpwarden/internal/report"
	"github.com/labibkamran/mcpwarden/internal/score"
)

const projectURL = "https://github.com/labibkamran/mcpwarden"

func runScan(args []string, stdout, stderr io.Writer, version string) int {
	opts, err := ParseScanArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printScanUsage(stdout)
		return ExitOK
	}
	if err == nil {
		err = checkSupported(opts)
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcpwarden scan: %v\nRun \"mcpwarden scan -h\" for usage.\n", err)
		return ExitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results := engine.Run(ctx, opts.Targets, engineOptions(opts, version))
	if err := writeReport(opts.Output, stdout, results); err != nil {
		fmt.Fprintf(stderr, "mcpwarden scan: write report: %v\n", err)
		return ExitError
	}
	return exitCode(results, opts.FailOn)
}

func checkSupported(opts ScanOptions) error {
	if opts.ConfigPath != "" {
		return errors.New("--config: scanning MCP client config files arrives in milestone 3")
	}
	if opts.Format != "text" {
		return fmt.Errorf("--format %s: json and sarif reports arrive in milestone 4", opts.Format)
	}
	return nil
}

func engineOptions(opts ScanOptions, version string) engine.Options {
	return engine.Options{
		Concurrency: opts.Concurrency,
		Checks:      check.Select(opts.Rules),
		Probe: probe.Options{
			Timeout:       opts.Timeout,
			UserAgent:     fmt.Sprintf("mcpwarden/%s (+%s)", version, projectURL),
			ClientVersion: version,
			Headers:       opts.Headers,
		},
	}
}

func writeReport(path string, stdout io.Writer, results []engine.Result) (err error) {
	if path == "" {
		return report.Text(stdout, results)
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return report.Text(f, results)
}

func exitCode(results []engine.Result, failOn check.Severity) int {
	unreachable := false
	for _, r := range results {
		if score.Fails(r.Findings, failOn) {
			return ExitFindings
		}
		unreachable = unreachable || r.Status == engine.StatusUnreachable
	}
	if unreachable {
		return ExitError
	}
	return ExitOK
}
