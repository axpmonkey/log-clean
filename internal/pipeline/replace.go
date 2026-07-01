package pipeline

import (
	"sort"
	"strings"
)

// ReplaceLine runs Pass 2 over a single line: every accepted match is
// substituted with its registry token (pseudonymized matches) or
// "SECRET_REDACTED" (redacted matches). Claim-only matches (Category == "",
// not Redact) are left in place in the output -- their only purpose is to
// occupy a span so later detectors skip it (e.g. UUIDs, per Decision 6).
func (p *Pipeline) ReplaceLine(line string) string {
	matches := p.walk(line)
	if len(matches) == 0 {
		return line
	}

	// walk() returns matches in detector-claim order, not left-to-right
	// position order (an earlier detector in the list can match later in the
	// line than a subsequent detector matches earlier in it). Sort by
	// position before building output; claimed spans never overlap, so this
	// sort alone is sufficient.
	sort.Slice(matches, func(i, j int) bool { return matches[i].Span.Start < matches[j].Span.Start })

	var sb strings.Builder
	pos := 0
	for _, m := range matches {
		if !m.Redact && m.Category == "" {
			continue // claim-only match, leave original text in place
		}
		sb.WriteString(line[pos:m.Span.Start])
		if m.Redact {
			sb.WriteString(SecretPlaceholder)
			p.replacementCounts["SECRET"]++
		} else if tok, ok := p.Registry.Lookup(m.Category, m.Value); ok {
			sb.WriteString(tok)
			p.replacementCounts[m.Category]++
		} else {
			// Pass 1 should have registered every non-redacted match it
			// found via the same walk; reaching this means Pass 1 and Pass 2
			// disagreed about what matched, which is a pipeline bug, not a
			// user-facing condition. Surface it loudly rather than silently
			// emitting the original (unredacted) value.
			sb.WriteString("TOKEN_MISSING_" + m.Category)
		}
		pos = m.Span.End
	}
	sb.WriteString(line[pos:])
	return sb.String()
}
