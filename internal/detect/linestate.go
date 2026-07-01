package detect

import "sort"

// LineState tracks the spans already claimed by earlier detectors on the
// current line. Per plan Decision 3, any overlap with a claimed span -- not
// just full containment -- protects a candidate; partial overlaps are
// rejected outright rather than matched around, keeping replacement
// deterministic.
type LineState struct {
	spans []Span // kept sorted by Start
}

// NewLineState returns an empty LineState, ready for a fresh line.
func NewLineState() *LineState {
	return &LineState{}
}

// IsProtected reports whether [start, end) overlaps any already-claimed span.
// spans is kept sorted by Start, so a binary search finds the first span that
// could possibly start at or after `start`; the only other candidate is the
// one span immediately before it (which starts earlier but may extend past
// `start`). That makes this O(log n) instead of scanning every claimed span,
// which matters on pathological lines with thousands of matches.
func (ls *LineState) IsProtected(start, end int) bool {
	// i is the first span with Start >= start.
	i := sort.Search(len(ls.spans), func(i int) bool { return ls.spans[i].Start >= start })
	// That span overlaps iff it begins before `end`.
	if i < len(ls.spans) && ls.spans[i].Start < end {
		return true
	}
	// The span just before i starts earlier; it overlaps iff it extends past
	// `start`.
	if i > 0 && ls.spans[i-1].End > start {
		return true
	}
	return false
}

// Claim records span as claimed, keeping spans ordered by Start. Callers must
// not claim a span that overlaps an existing one; check IsProtected first.
func (ls *LineState) Claim(span Span) {
	i := sort.Search(len(ls.spans), func(i int) bool { return ls.spans[i].Start >= span.Start })
	ls.spans = append(ls.spans, Span{})
	copy(ls.spans[i+1:], ls.spans[i:])
	ls.spans[i] = span
}

// Spans returns the claimed spans in order, for tests and debugging.
func (ls *LineState) Spans() []Span {
	out := make([]Span, len(ls.spans))
	copy(out, ls.spans)
	return out
}
