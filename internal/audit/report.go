package audit

import (
	"fmt"
	"strings"
)

// Report formats findings for the _audit.txt output: each finding listed
// with file, line, pattern name, and excerpt, followed by a severity tally.
func Report(findings []Finding) string {
	var sb strings.Builder
	counts := map[Severity]int{}
	for _, f := range findings {
		fmt.Fprintf(&sb, "[%s] %s:%d: %s (%q)\n    %s\n", f.Severity, f.File, f.Line, f.Pattern, f.Match, f.Excerpt)
		counts[f.Severity]++
	}
	fmt.Fprintf(&sb, "\nSummary: High=%d, Medium=%d\n", counts[SeverityHigh], counts[SeverityMedium])
	return sb.String()
}

// HasHigh reports whether findings contains at least one High-severity
// finding -- the condition --strict mode gates on (plan: audit pass spec).
func HasHigh(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityHigh {
			return true
		}
	}
	return false
}
