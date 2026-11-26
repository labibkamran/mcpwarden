// Flag parsing helpers. stringList backs repeatable flags and never rejects a
// value, so the flag package cannot echo a token in its error message (FR-022);
// values are validated after parsing. parseInterspersed lets flags appear before,
// between or after URLs, because the flag package alone stops at the first one.

package cli

import (
	"flag"
	"strings"
)

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

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
