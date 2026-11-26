package main

import (
	"flag"
	"strings"
)

// stringList is a repeatable flag such as --header or --disable. Set never
// fails, so the flag package never echoes a raw value in an error message;
// values are validated after parsing, where secrets can be kept out (FR-022).
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments, as in "scan https://a --format json https://b".
// The flag package alone stops at the first positional argument.
// It returns the positional arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
