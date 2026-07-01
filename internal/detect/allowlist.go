package detect

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"
)

// minAllowlistEntryLength gates the short/ambiguous-entry guard added to the
// plan: a short allowlist entry (e.g. "db1") will also match as a substring
// inside unrelated, longer identifiers (e.g. "db10", "adb1x"), silently
// corrupting them. This doesn't reject short entries outright -- customers
// may have genuinely short, distinctive hostnames -- it just surfaces a
// warning so the operator can judge whether the entry is safe.
const minAllowlistEntryLength = 4

// LoadAllowlist parses a customer hostname allowlist: one hostname per
// non-empty, non-comment line ('#' starts a comment). Returned entries are
// sorted longest-first, since the allowlist detector matches literal
// substrings and must try longer, more specific hostnames before shorter
// ones that might be a substring of them (plan: allowlist detector spec,
// "longest-match-first").
//
// This is a small, human-edited config file, not log content, so it doesn't
// need Decision 7's 16 MB line buffer -- bufio.Scanner's default line length
// is more than enough for a hostname-per-line file.
func LoadAllowlist(r io.Reader) (entries []string, warnings []string, err error) {
	scanner := bufio.NewScanner(r)
	var raw []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw = append(raw, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading allowlist: %w", err)
	}

	for _, h := range raw {
		if len(h) < minAllowlistEntryLength {
			warnings = append(warnings, fmt.Sprintf(
				"allowlist entry %q is shorter than %d characters and may match as a substring inside unrelated identifiers (e.g. inside a longer hostname); consider using a more distinctive value",
				h, minAllowlistEntryLength))
		}
	}
	for i, a := range raw {
		for j, b := range raw {
			if i == j || len(a) >= len(b) {
				continue
			}
			if strings.Contains(b, a) {
				warnings = append(warnings, fmt.Sprintf(
					"allowlist entry %q is a substring of %q; longest-match-first ordering means %q alone will never be the one that matches inside %q",
					a, b, a, b))
			}
		}
	}

	sort.Slice(raw, func(i, j int) bool { return len(raw[i]) > len(raw[j]) })
	return raw, warnings, nil
}

// AllowlistDetector finds literal occurrences of customer-supplied
// hostnames anywhere in a line, including inside compound paths and strings
// like "/var/log/db-prod-01-archive/" where a word-boundary-based detector
// would miss the embedded hostname. This is the only detector that does
// substring matching rather than word-boundary matching (plan: allowlist
// detector spec), and per Decision 4 it runs last, after every other
// detector has already claimed its spans.
type AllowlistDetector struct {
	// hosts is sorted longest-first by NewAllowlistDetector, so that within
	// a single Detect() call, longer/more-specific hostnames claim their
	// span (via the pipeline's first-come overlap rule) before a shorter
	// hostname that happens to be a substring of them is tried.
	hosts []string
	// caseInsensitive, when set (from detectors.allowlist.case_insensitive),
	// matches entries regardless of case. The tokenized Value is still the
	// exact text from the log line, not the allowlist entry, so a round-trip
	// through reverse mode restores the original casing.
	caseInsensitive bool
}

// NewAllowlistDetector builds a detector from already-loaded entries
// (typically the output of LoadAllowlist). It re-sorts defensively in case
// the caller passes an unsorted list. When caseInsensitive is true, matching
// ignores case.
func NewAllowlistDetector(entries []string, caseInsensitive bool) AllowlistDetector {
	sorted := make([]string, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	return AllowlistDetector{hosts: sorted, caseInsensitive: caseInsensitive}
}

func (AllowlistDetector) Name() string { return "allowlist" }

func (d AllowlistDetector) Detect(line string) []Match {
	// For case-insensitive matching, search within a lowercased copy of the
	// line. Hostnames are ASCII, so lowercasing preserves byte length and
	// offsets -- the span found in `hay` maps directly back onto `line`.
	hay := line
	if d.caseInsensitive {
		hay = strings.ToLower(line)
	}
	var matches []Match
	for _, host := range d.hosts {
		if host == "" {
			continue
		}
		needle := host
		if d.caseInsensitive {
			needle = strings.ToLower(host)
		}
		start := 0
		for {
			idx := strings.Index(hay[start:], needle)
			if idx < 0 {
				break
			}
			s := start + idx
			e := s + len(needle)
			matches = append(matches, Match{
				Span:     Span{Start: s, End: e},
				Value:    line[s:e],
				Category: "HOST",
			})
			start = e
		}
	}
	return matches
}
