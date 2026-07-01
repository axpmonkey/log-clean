// Package detect defines the Detector interface and the per-line span
// bookkeeping that prevents one detector from matching inside text another
// detector already claimed.
package detect

// Span is a half-open byte-offset range [Start, End) within a line.
type Span struct {
	Start, End int
}

// Match is a candidate detection emitted by a Detector for a single line.
type Match struct {
	Span Span
	// Value is the exact matched substring, used as the token registry's
	// lookup key so the same original value always maps to the same token.
	Value string
	// Category is the token category (e.g. "HOST", "IPV4"). Leave empty for
	// claim-only matches that should occupy a span but never be replaced or
	// registered (e.g. the UUID detector, per plan Decision 6).
	Category string
	// Redact marks a match as a secret: replaced with SECRET_REDACTED and
	// never written to the token registry or mapping file (plan Decision 5).
	Redact bool
}

// Detector inspects a single line and returns every candidate match it finds,
// independent of what any other detector has done. Detectors do not need to
// consult LineState themselves -- the pipeline applies span-claiming
// centrally, in detector-list order, so the overlap rule has exactly one
// implementation (see LineState.IsProtected) rather than one per detector.
type Detector interface {
	// Name identifies the detector for runlog/audit output.
	Name() string
	// Detect returns every candidate match in line. Order within the
	// returned slice does not matter; the pipeline sorts by position when
	// needed.
	Detect(line string) []Match
}
