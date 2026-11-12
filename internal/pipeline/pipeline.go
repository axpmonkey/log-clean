// Package pipeline orchestrates the two-pass sanitization run described in
// plan Decision 2: Pass 1 (scan.go) scans every line to build the token
// registry, Pass 2 (replace.go) substitutes tokens. Both passes drive the
// same detector walk (walk, below) so they can never discover a different set
// of matches -- a divergence there would mean Pass 2 tries to replace a value
// Pass 1 never registered.
package pipeline

import (
	"net/netip"

	"sas-log-sanitize/internal/detect"
	"sas-log-sanitize/internal/tokenize"
)

// SecretPlaceholder is the text that replaces any fully-redacted secret,
// whether a single-line credential/secret (ReplaceLine) or a whole line
// inside a multi-line PEM private-key block (Run's file-level block
// redactor). Kept in one place so both paths emit the identical marker.
const SecretPlaceholder = "SECRET_REDACTED"

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

	// IPv4SkipRanges mirrors detectors.ipv4.skip_ranges: CIDR blocks the IPv4
	// detector leaves untokenized. Held here (in addition to being baked into
	// the IPv4 detector) so Run can hand the same ranges to the audit scanner,
	// keeping its unredacted-ipv4 rule from flagging the intentionally-skipped
	// addresses. Nil when no skip ranges are configured.
	IPv4SkipRanges []netip.Prefix

	// replacementCounts tracks actual substitution occurrences per category
	// (plus the synthetic "SECRET" key for redactions) across every
	// ReplaceLine call, for the mapping file's stats.replacements_by_category
	// field. This is occurrence counts, not unique-value counts -- that's
	// what Registry.Count already provides.
	replacementCounts map[string]int

	// scanDetectors is how many of Detectors Pass 1 ran: everything before
	// the known-values sweep EnableKnownValuesSweep appends. Only those
	// detectors appear in a DetectorMask. sweepEnabled is set with it.
	scanDetectors int
	sweepEnabled  bool
}

// DetectorMask records which detectors returned at least one candidate on
// a line (bit k for Detectors[k], k < 32). Detectors are pure functions of
// the line, so in Pass 2 a detector whose bit is clear would find nothing
// again on the same line and can be skipped without changing any claim.
// Pass 1 records each line's mask (see maskSidecar) so Pass 2 runs only the
// detectors that matter plus the known-values sweep.
type DetectorMask = uint32

// AllDetectors runs every detector: the mask for lines with no Pass 1
// record.
const AllDetectors DetectorMask = ^DetectorMask(0)

// New creates a Pipeline with detectors run in the given order.
func New(detectors []detect.Detector) *Pipeline {
	return &Pipeline{
		Detectors:         detectors,
		Registry:          tokenize.NewRegistry(),
		replacementCounts: make(map[string]int),
	}
}

// CountLineRedaction records one whole-line redaction in the replacement
// stats' synthetic "SECRET" bucket. Used by Run's file-level PEM block
// redactor, which bypasses the per-line detector walk (the key body is
// invisible to every single-line detector) and so must account for its own
// redactions the way ReplaceLine does for the secrets it substitutes.
func (p *Pipeline) CountLineRedaction() {
	p.replacementCounts["SECRET"]++
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

// EnableKnownValuesSweep appends the known-values sweep (see
// detect.KnownValuesDetector) as the last detector, built from everything
// the registry holds now. Run calls it between Pass 1 and Pass 2, once the
// registry is complete; it must not be called before Pass 1 finishes, or
// values first seen later in the bundle would be missed. It returns the
// swept values (nil when there are none).
func (p *Pipeline) EnableKnownValuesSweep() []detect.KnownValue {
	values := detect.SweepValues(p.Registry.Values("USER"), p.Registry.Values("HOST"))
	p.scanDetectors, p.sweepEnabled = len(p.Detectors), true
	if d := detect.NewKnownValuesDetector(values); d != nil {
		p.Detectors = append(p.Detectors, d)
	}
	return values
}

// walk runs every detector over line in detector-list order, accepting only
// candidates that don't overlap a span already claimed by an earlier
// detector, and returns the accepted matches in claim order (not
// necessarily left-to-right position order).
func (p *Pipeline) walk(line string) []detect.Match {
	accepted, _ := p.walkMasked(line, AllDetectors)
	return accepted
}

// walkMasked is walk, skipping each detector k < scanDetectors (and < 32)
// whose bit in mask is clear. It also returns the mask of detectors that
// produced at least one candidate.
func (p *Pipeline) walkMasked(line string, mask DetectorMask) ([]detect.Match, DetectorMask) {
	state := detect.NewLineState()
	var accepted []detect.Match
	var found DetectorMask
	maskable := len(p.Detectors)
	if p.sweepEnabled {
		maskable = p.scanDetectors // the sweep always runs
	}
	for k, d := range p.Detectors {
		if k < maskable && k < 32 && mask&(1<<k) == 0 {
			continue
		}
		if pf, ok := d.(detect.Prefilter); ok && !pf.MightMatch(line) {
			continue
		}
		cands := d.Detect(line)
		if len(cands) > 0 && k < 32 {
			found |= 1 << k
		}
		for _, m := range cands {
			if state.IsProtected(m.Span.Start, m.Span.End) {
				continue
			}
			if p.shouldIgnore(m) {
				continue
			}
			// SAS internal accounts (sasadm@saspw, ...) stay readable. The
			// span is still claimed so no later detector -- notably the
			// known-values sweep -- tokenizes it instead.
			if !m.Redact && detect.IsSASInternalAccount(line, m.Span.Start, m.Span.End) {
				state.Claim(m.Span)
				continue
			}
			state.Claim(m.Span)
			accepted = append(accepted, m)
		}
	}
	return accepted, found
}

// shouldIgnore reports whether the ignore list suppresses match m. It is
// deliberately scoped to host-shaped matches only: the ignore list names
// hostnames/domains ("*.sas.com"), so applying it to a match's whole value
// indiscriminately would wrongly suppress, say, an email address or LDAP DN
// whose text merely ends in an ignored domain (e.g. "jdoe@corp.sas.com"),
// leaking the username. So a bare HOST is matched directly; a URL or UNC
// path is matched only on its embedded host/server -- and when that host is
// ignored the whole URL/UNC match is dropped (not claimed), letting the
// finer-grained detectors that run afterward still tokenize any sensitive
// interior text (a username in a query string, say) around the ignored host.
func (p *Pipeline) shouldIgnore(m detect.Match) bool {
	if p.Ignore.Empty() {
		return false
	}
	switch m.Category {
	case "HOST":
		return p.Ignore.Matches(m.Value)
	case "URL":
		if host, ok := detect.EmbeddedHost(m.Value); ok {
			return p.Ignore.Matches(host)
		}
	case "UNC":
		if server, ok := detect.EmbeddedUNCServer(m.Value); ok {
			return p.Ignore.Matches(server)
		}
	}
	return false
}
