package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const redactedCommandValue = "[REDACTED]"

// sensitiveCommandFlags covers values that must not be copied into an execution
// log if a future scanner option carries credentials or other secrets. The scan
// commands currently use none of these flags, but keeping redaction at the log
// boundary makes adding one fail-safe by default.
var sensitiveCommandFlags = map[string]struct{}{
	"-api-key":   {},
	"--api-key":  {},
	"-apikey":    {},
	"--apikey":   {},
	"-auth":      {},
	"--auth":     {},
	"-cookie":    {},
	"--cookie":   {},
	"-header":    {},
	"--header":   {},
	"-headers":   {},
	"--headers":  {},
	"-password":  {},
	"--password": {},
	"-proxy":     {},
	"--proxy":    {},
	"-secret":    {},
	"--secret":   {},
	"-token":     {},
	"--token":    {},
}

// writeCommandLog writes one structured command record. JSON preserves the exact
// argv boundaries, including spaces and shell metacharacters in paths, without
// pretending the line is safe to paste into a particular shell. The executable is
// argv[0], followed by the exact arguments passed to exec.Command.
func writeCommandLog(w io.Writer, phase, executable string, args []string) {
	if w == nil {
		return
	}
	argv := make([]string, 1, len(args)+1)
	argv[0] = executable
	argv = append(argv, redactCommandArgs(args)...)
	encoded, err := json.Marshal(argv)
	if err != nil {
		return // []string cannot fail to marshal; logging must never fail a scan
	}
	_, _ = fmt.Fprintf(w, "[CMD] phase=%s argv=%s\n", phase, encoded)
}

func redactCommandArgs(args []string) []string {
	redacted := append([]string(nil), args...)
	for i := 0; i < len(redacted); i++ {
		flag, _, inline := strings.Cut(redacted[i], "=")
		if inline && isSensitiveCommandFlag(flag) {
			redacted[i] = flag + "=" + redactedCommandValue
			continue
		}
		if !inline && isSensitiveCommandFlag(redacted[i]) && i+1 < len(redacted) {
			redacted[i+1] = redactedCommandValue
			i++
		}
	}
	return redacted
}

func isSensitiveCommandFlag(arg string) bool {
	_, ok := sensitiveCommandFlags[strings.ToLower(strings.TrimSpace(arg))]
	return ok
}
