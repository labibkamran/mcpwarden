// JSON with comments, as VS Code writes it: // and /* */ comments and trailing commas are replaced
// by spaces outside strings, so the result is plain JSON with the same byte offsets and lines.

package target

import "bytes"

func stripJSONC(src []byte) []byte {
	b := bytes.Clone(src)
	scanCode(b, func(i int) int { return blankComment(b, i) })
	scanCode(b, func(i int) int {
		if b[i] == ',' && closesNext(b[i+1:]) {
			b[i] = ' '
		}
		return i
	})
	return b
}

func scanCode(b []byte, visit func(i int) int) {
	inString := false
	for i := 0; i < len(b); i++ {
		switch {
		case inString && b[i] == '\\':
			i++
		case inString && b[i] == '"':
			inString = false
		case inString:
		case b[i] == '"':
			inString = true
		default:
			i = visit(i)
		}
	}
}

func blankComment(b []byte, i int) int {
	if b[i] != '/' || i+1 >= len(b) {
		return i
	}
	var end int
	switch b[i+1] {
	case '/':
		end = i + bytes.IndexByte(b[i:], '\n')
		if end < i {
			end = len(b)
		}
	case '*':
		end = len(b)
		if n := bytes.Index(b[i+2:], []byte("*/")); n >= 0 {
			end = i + 2 + n + 2
		}
	default:
		return i
	}
	for j := i; j < end; j++ {
		if b[j] != '\n' && b[j] != '\r' {
			b[j] = ' '
		}
	}
	return end - 1
}

func closesNext(rest []byte) bool {
	rest = bytes.TrimLeft(rest, " \t\r\n")
	return len(rest) > 0 && (rest[0] == '}' || rest[0] == ']')
}
