// The scan command: parse the options, then run the scan. Usage errors exit 2 (FR-004) with a
// pointer to -h. Until the engine is wired in, a valid scan also exits 2.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, err := ParseScanArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		printScanUsage(stdout)
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "mcpwarden scan: %v\nRun \"mcpwarden scan -h\" for usage.\n", err)
		return ExitError
	}
	fmt.Fprintf(stderr, "mcpwarden scan: scanning is not implemented yet (%d targets parsed)\n", len(opts.Targets))
	return ExitError
}
