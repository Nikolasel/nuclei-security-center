package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	redactedCommandValue       = "[REDACTED]"
	maxLoggedTemplatePaths     = 16
	templatePathSampleEachSide = 4
	templatePathSummaryFormat  = "[%d template paths omitted]"
)

type commandTool uint8

const (
	commandToolUnknown commandTool = iota
	commandToolNuclei
	commandToolNaabu
)

// sensitiveCommandFlags covers values that must not be copied into an execution
// log if a scanner option carries credentials or other secrets. It includes the
// real Nuclei spellings and conservative aliases so redaction stays fail-closed
// if a future scanner option uses a new long-form spelling.
var sensitiveCommandFlags = map[string]struct{}{
	"-api-key":            {},
	"--api-key":           {},
	"-apikey":             {},
	"--apikey":            {},
	"-client-key":         {},
	"--client-key":        {},
	"-ck":                 {},
	"--ck":                {},
	"-cookie":             {},
	"--cookie":            {},
	"-dast-server-token":  {},
	"--dast-server-token": {},
	"-dtst":               {},
	"--dtst":              {},
	"-header":             {},
	"--header":            {},
	"-headers":            {},
	"--headers":           {},
	"-interactsh-token":   {},
	"--interactsh-token":  {},
	"-itoken":             {},
	"--itoken":            {},
	"-password":           {},
	"--password":          {},
	"-p":                  {},
	"--p":                 {},
	"-proxy":              {},
	"--proxy":             {},
	"-proxy-auth":         {},
	"--proxy-auth":        {},
	"-secret":             {},
	"--secret":            {},
	"-secret-file":        {},
	"--secret-file":       {},
	"-sf":                 {},
	"--sf":                {},
	"-token":              {},
	"--token":             {},
	"-var":                {},
	"--var":               {},
}

var sensitiveCommandFlagSuffixes = []string{
	"-api-key",
	"-apikey",
	"-client-key",
	"-header",
	"-headers",
	"-password",
	"-proxy-auth",
	"-proxy",
	"-secret",
	"-token",
	"-var",
}

// writeCommandLog writes one structured command record. JSON preserves the exact
// argv boundaries, including spaces and shell metacharacters in paths, without
// pretending the line is safe to paste into a particular shell. The executable is
// argv[0], followed by the arguments passed to exec.Command. Large repeated
// -templates lists retain a small first/last sample and summarize the middle when
// they exceed maxLoggedTemplatePaths because resolved template IDs are persisted
// on the scan and a viewer-visible execution log should not be dominated by a
// megabyte-long single line. Redaction is phase-aware because Nuclei's -p is a
// proxy value while naabu's -p is a port value.
func writeCommandLog(w io.Writer, phase, executable string, args []string) {
	if w == nil {
		return
	}
	argv := make([]string, 1, len(args)+1)
	argv[0] = executable
	argv = append(argv, redactCommandArgs(compactCommandArgs(args), commandToolForPhase(phase))...)
	encoded, err := json.Marshal(argv)
	if err != nil {
		return // []string cannot fail to marshal; logging must never fail a scan
	}
	_, _ = fmt.Fprintf(w, "[CMD] phase=%s argv=%s\n", phase, encoded)
}

func compactCommandArgs(args []string) []string {
	compacted := make([]string, 0, len(args))
	for i := 0; i < len(args); {
		if isTemplateFlag(args[i]) && i+1 < len(args) {
			flag := args[i]
			paths := make([]string, 0)
			for i < len(args) && isTemplateFlag(args[i]) && i+1 < len(args) {
				paths = append(paths, args[i+1])
				i += 2
			}
			if len(paths) > maxLoggedTemplatePaths {
				compacted = appendTemplatePathSummary(compacted, flag, paths)
			} else {
				for _, path := range paths {
					compacted = append(compacted, flag, path)
				}
			}
			continue
		}
		compacted = append(compacted, args[i])
		i++
	}
	return compacted
}

// appendTemplatePathSummary keeps the sampling safe independently of the
// threshold constant: a future lower threshold cannot make the slices below
// exceed the available path list and panic the scan's logging path.
func appendTemplatePathSummary(args []string, flag string, paths []string) []string {
	sampleEachSide := templatePathSampleEachSide
	if maxSample := len(paths) / 2; sampleEachSide > maxSample {
		sampleEachSide = maxSample
	}
	for _, path := range paths[:sampleEachSide] {
		args = append(args, flag, path)
	}
	omitted := len(paths) - 2*sampleEachSide
	args = append(args, flag, fmt.Sprintf(templatePathSummaryFormat, omitted))
	for _, path := range paths[len(paths)-sampleEachSide:] {
		args = append(args, flag, path)
	}
	return args
}

func isTemplateFlag(arg string) bool {
	return arg == "-templates" || arg == "--templates"
}

func commandToolForPhase(phase string) commandTool {
	switch {
	case phase == "nuclei":
		return commandToolNuclei
	case strings.HasPrefix(phase, "naabu-"):
		return commandToolNaabu
	default:
		return commandToolUnknown
	}
}

func redactCommandArgs(args []string, tool commandTool) []string {
	redacted := append([]string(nil), args...)
	for i := 0; i < len(redacted); i++ {
		flag, _, inline := strings.Cut(redacted[i], "=")
		if inline && isSensitiveCommandFlag(flag, tool) {
			redacted[i] = flag + "=" + redactedCommandValue
			continue
		}
		if !inline && isSensitiveCommandFlag(redacted[i], tool) && i+1 < len(redacted) {
			redacted[i+1] = redactedCommandValue
			i++
		}
	}
	return redacted
}

func isSensitiveCommandFlag(arg string, tool commandTool) bool {
	flag := strings.TrimSpace(arg)
	if flag == "-H" || flag == "-V" {
		return true
	}
	normalized := strings.ToLower(flag)
	if tool == commandToolNaabu && (normalized == "-p" || normalized == "--p") {
		return false
	}
	if _, ok := sensitiveCommandFlags[normalized]; ok {
		return true
	}
	for _, suffix := range sensitiveCommandFlagSuffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}
