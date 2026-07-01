// Package pipeline orchestrates the two-pass sanitization run described in
// plan Decision 2: Pass 1 (scan.go) scans every line to build the token
// registry, Pass 2 (replace.go) substitutes tokens. Both passes drive the
// same detector walk (walk, below) so they can never discover a different set
// of matches -- a divergence there would mean Pass 2 tries to replace a value
// Pass 1 never registered.
package pipeline

import (
	"sas-log-sanitize/internal/detect"
	"sas-log-sanitize/internal/tokenize"
)

// Pipeline runs an ordered list of detectors over lines in two passes.
type Pipeline struct {
	// Detectors run in this exact order on every line; each detector's
	// candidates are filtered against spans already claimed by earlier
	// detectors in the same list (plan Decision 4).
	Detectors []detect.Detector
	Registry  *tokenize.Registry

	// Ignore, if set, suppresses any detector match whose value it matches
	// (see detect.IgnoreList) -- the original text is left untouched rather
	// than tokenized. Left as the zero value (Empty()) when no --ignorelist
	// is configured, so the check is a no-op on the common path.
	Ignore detect.IgnoreList

	// replacementCounts tracks actual substitution occurrences per category
	// (plus the synthetic "SECRET" key for redactions) across every
	// ReplaceLine call, for the mapping file's stats.replacements_by_category
	// field. This is occurrence counts, not unique-value counts -- that's
	// what Registry.Count already provides.
	replacementCounts map[string]int
}

// New creates a Pipeline with detectors run in the given order.
func New(detectors []detect.Detector) *Pipeline {
	return &Pipeline{
		Detectors:         detectors,
		Registry:          tokenize.NewRegistry(),
		replacementCounts: make(map[string]int),
	}
}

// ReplacementCounts returns a copy of the per-category replacement
// occurrence counts accumulated so far.
func (p *Pipeline) ReplacementCounts() map[string]int {
	out := make(map[string]int, len(p.replacementCounts))
	for k, v := range p.replacementCounts {
		out[k] = v
	}
	return out
}

// walk runs every detector over line in detector-list order, accepting only
// candidates that don't overlap a span already claimed by an earlier
// detector, and returns the accepted matches in claim order (not
// necessarily left-to-right position order).
func (p *Pipeline) walk(line string) []detect.Match {
	state := detect.NewLineState()
	var accepted []detect.Match
	for _, d := range p.Detectors {
		for _, m := range d.Detect(line) {
			if state.IsProtected(m.Span.Start, m.Span.End) {
				continue
			}
			if !p.Ignore.Empty() && p.Ignore.Matches(m.Value) {
				continue
			}
			state.Claim(m.Span)
			accepted = append(accepted, m)
		}
	}
	return accepted
}
