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
func (ls *LineState) IsProtected(start, end int) bool {
	for _, s := range ls.spans {
		if start < s.End && end > s.Start {
			return true
		}
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
