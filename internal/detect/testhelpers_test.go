package detect

import (
	"strings"
	"testing"
)

// resolveOverlaps reduces a detector's raw candidate list the same way
// pipeline.Pipeline.walk does: first-come-first-claimed, any overlap with an
// already-claimed span discards the later candidate. Detectors that combine
// several internal sub-patterns (e.g. CredentialsDetector) can return
// candidates that overlap each other; in production that's resolved by the
// pipeline, so unit tests that call Detect() directly need to apply the same
// resolution to see realistic output.
func resolveOverlaps(matches []Match) []Match {
	state := NewLineState()
	var accepted []Match
	for _, m := range matches {
		if state.IsProtected(m.Span.Start, m.Span.End) {
			continue
		}
		state.Claim(m.Span)
		accepted = append(accepted, m)
	}
	return accepted
}

// expectSubstringMatches verifies that detecting on line produces exactly one
// match per entry in wantValues, each with the given category, at the
// position where that substring actually occurs in line (computed via
// sequential strings.Index rather than hand-counted byte offsets, which are
// easy to get wrong and tedious to re-verify).
func expectSubstringMatches(t *testing.T, matches []Match, line string, wantValues []string, wantCategory string) {
	t.Helper()
	if len(matches) != len(wantValues) {
		t.Fatalf("got %d matches, want %d: %+v", len(matches), len(wantValues), matches)
	}
	searchFrom := 0
	for i, want := range wantValues {
		idx := strings.Index(line[searchFrom:], want)
		if idx < 0 {
			t.Fatalf("test setup error: %q not found in line %q after offset %d", want, line, searchFrom)
		}
		start := searchFrom + idx
		end := start + len(want)
		searchFrom = end

		if matches[i].Span != (Span{start, end}) {
			t.Errorf("match %d span = %v, want %v (for %q)", i, matches[i].Span, Span{start, end}, want)
		}
		if matches[i].Value != want {
			t.Errorf("match %d value = %q, want %q", i, matches[i].Value, want)
		}
		if matches[i].Category != wantCategory {
			t.Errorf("match %d category = %q, want %q", i, matches[i].Category, wantCategory)
		}
	}
}
