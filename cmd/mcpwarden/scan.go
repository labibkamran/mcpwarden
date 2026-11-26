package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/labibkamran/mcpwarden/internal/check"
	"github.com/labibkamran/mcpwarden/internal/target"
)

const (
	defaultTimeout     = 10 * time.Second // FR-012
	defaultConcurrency = 16
	// defaultFailOn matches the fail_on example in SRS 5.2.
	defaultFailOn = "high"
)

const scanUsage = `Usage: mcpwarden scan [URL...] [flags]

Scans MCP servers by URL and MCP client config files.
Scan only servers you own or are authorized to test.

Flags:`

// scanOptions is the validated configuration of one scan run.
type scanOptions struct {
	targets     []target.Target
	configPath  string
	format      string
	output      string
	failOn      check.Severity
	timeout     time.Duration
	concurrency int
	headers     http.Header
	rules       check.RuleSelection
}

// scanFlags holds raw flag values before validation.
type scanFlags struct {
	configPath, format, output, failOn string
	timeout                            time.Duration
	concurrency                        int
	headers, enable, disable           stringList
}

// runScan implements "mcpwarden scan" (FR-002, FR-003) and returns the exit code.
func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := parseScanArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printScanUsage(stdout)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcpwarden scan: %v\nRun \"mcpwarden scan -h\" for usage.\n", err)
		return exitError
	}
	// ponytail: the probe and check engine land in M2; until then a valid scan cannot run.
	fmt.Fprintf(stderr, "mcpwarden scan: scanning is not implemented yet (%d targets parsed)\n", len(opts.targets))
	return exitError
}

// parseScanArgs parses and validates the scan command's arguments.
// It returns flag.ErrHelp when -h or --help was given.
func parseScanArgs(args []string) (scanOptions, error) {
	var f scanFlags
	urls, err := parseInterspersed(newScanFlagSet(&f), args)
	if err != nil {
		return scanOptions{}, err
	}
	return f.validate(urls)
}

func newScanFlagSet(f *scanFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // runScan prints errors and usage itself
	fs.StringVar(&f.configPath, "config", "", "scan the MCP client config file at `PATH`")
	fs.StringVar(&f.format, "format", "text", "report `format`: text, json or sarif")
	fs.StringVar(&f.output, "output", "", "write the report to `FILE` instead of stdout")
	fs.StringVar(&f.failOn, "fail-on", defaultFailOn,
		"exit 1 on findings at or above this `severity`: low, medium, high or critical")
	fs.DurationVar(&f.timeout, "timeout", defaultTimeout, "timeout for each request")
	fs.IntVar(&f.concurrency, "concurrency", defaultConcurrency, "number of targets scanned at once")
	fs.Var(&f.headers, "header", "add a request header \"Name: value\" (repeatable)")
	fs.Var(&f.enable, "enable", "enable a rule by `ID` (repeatable)")
	fs.Var(&f.disable, "disable", "disable a rule by `ID` (repeatable)")
	return fs
}

func printScanUsage(w io.Writer) {
	fs := newScanFlagSet(&scanFlags{})
	fs.SetOutput(w)
	fmt.Fprintln(w, scanUsage)
	fs.PrintDefaults()
}

func (f *scanFlags) validate(rawURLs []string) (scanOptions, error) {
	targets, err := parseTargets(rawURLs)
	if err != nil {
		return scanOptions{}, err
	}
	if len(targets) == 0 && f.configPath == "" {
		return scanOptions{}, errors.New("nothing to scan: pass a server URL or --config PATH")
	}
	if !isReportFormat(f.format) {
		return scanOptions{}, fmt.Errorf("--format %q: want text, json or sarif", f.format)
	}
	failOn, err := check.ParseSeverity(f.failOn)
	if err != nil {
		return scanOptions{}, fmt.Errorf("--fail-on: %w", err)
	}
	if f.timeout <= 0 {
		return scanOptions{}, fmt.Errorf("--timeout %s: must be positive", f.timeout)
	}
	if f.concurrency < 1 {
		return scanOptions{}, fmt.Errorf("--concurrency %d: must be at least 1", f.concurrency)
	}
	headers, err := parseHeaders(f.headers)
	if err != nil {
		return scanOptions{}, err
	}
	rules, err := check.ParseRuleSelection(f.enable, f.disable)
	if err != nil {
		return scanOptions{}, err
	}
	return scanOptions{
		targets:     targets,
		configPath:  f.configPath,
		format:      f.format,
		output:      f.output,
		failOn:      failOn,
		timeout:     f.timeout,
		concurrency: f.concurrency,
		headers:     headers,
		rules:       rules,
	}, nil
}

// parseTargets normalizes server URLs and drops duplicates, keeping order.
// Errors name the argument by position rather than quoting it.
func parseTargets(rawURLs []string) ([]target.Target, error) {
	var targets []target.Target
	seen := make(map[string]bool)
	for i, raw := range rawURLs {
		t, err := target.ParseURL(raw)
		if err != nil {
			return nil, fmt.Errorf("target #%d: %w", i+1, err)
		}
		if seen[t.String()] {
			continue
		}
		seen[t.String()] = true
		targets = append(targets, t)
	}
	return targets, nil
}

func isReportFormat(format string) bool {
	switch format {
	case "text", "json", "sarif":
		return true
	default:
		return false
	}
}
