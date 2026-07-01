// Package audit re-scans sanitized output for patterns that look like
// residual PII -- a second line of defense in case a detector missed
// something during sanitization. Every rule in the plan's audit pass table
// is implemented here.
package audit

import (
	"regexp"

	"sas-log-sanitize/internal/detect"
)

// Severity ranks how confident a finding is. High-severity patterns have a
// low false-positive rate and are what --strict gates on; Medium-severity
// patterns are intentionally broad (see the rule comments below) and are
// expected to produce noise on real logs -- that's a deliberate tradeoff
// (false negatives are worse than false positives for a security tool), not
// a bug to fix by narrowing them.
type Severity int

const (
	SeverityMedium Severity = iota
	SeverityHigh
)

func (s Severity) String() string {
	if s == SeverityHigh {
		return "High"
	}
	return "Medium"
}

// Finding is a single suspicious-pattern hit in already-sanitized output.
type Finding struct {
	File     string
	Line     int
	Pattern  string // rule name, e.g. "unredacted-ipv4"
	Match    string // the suspicious substring itself
	Excerpt  string // the full line it was found on
	Severity Severity
}

// tokenShapePattern matches the sanitizer's own token format (CATEGORY_NNN).
// Used by the path-with-username rules to tell "the username here is
// already USER_NNN, nothing to flag" apart from "a real username leaked".
var tokenShapePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*_\d+$`)

// tokenSuffixPattern matches the "_NNN" tail of our own token format. Some
// category names end in a digit (IPV4, IPV6), so a broad word-shape rule
// like server-suffix-bare-word can otherwise match "IPV4" inside our own
// "IPV4_001" token and flag it as suspicious -- a false positive caused by
// our own naming scheme, not residual PII. suppressOwnTokenFragment treats
// any match immediately followed by "_NNN" as part of one of our tokens.
var tokenSuffixPattern = regexp.MustCompile(`^_\d+\b`)

func suppressOwnTokenFragment(line string, start, end int) bool {
	return tokenSuffixPattern.MatchString(line[end:])
}

type rule struct {
	name     string
	severity Severity
	pattern  *regexp.Regexp
	// suppress, if set, is called with the match's start/end offsets;
	// returning true skips the match. Used to share suppression heuristics
	// with the corresponding sanitization detector so the audit pass
	// doesn't flag text the detector intentionally chose not to touch, or
	// to filter out fragments of the sanitizer's own token format.
	suppress func(line string, start, end int) bool
	// find, if set, replaces pattern-based matching entirely for rules that
	// need more than "does this regex match" (e.g. checking a captured
	// group, or proximity between two separate patterns).
	find func(line string) [][2]int
}

// Scanner holds the set of audit rules to run against sanitized text.
type Scanner struct {
	rules []rule

	// Ignore, if set, mirrors the sanitization pipeline's --ignorelist: a
	// hostname/FQDN this scanner would otherwise flag as unredacted-fqdn is
	// suppressed if it matches, since the sanitizer intentionally left it
	// untouched (e.g. "*.sas.com") rather than missing it. Left as the zero
	// value (Empty()) when no --ignorelist is configured.
	Ignore detect.IgnoreList
}

// NewScanner returns a Scanner configured with every rule from the plan's
// audit pass table. Sanitized text should contain none of these -- every
// real instance should already have become a CATEGORY_NNN token or
// SECRET_REDACTED.
func NewScanner() *Scanner {
	s := &Scanner{}
	s.rules = []rule{
		// Shares detect.LooksLikeVersionString with the IPv4 detector so a
		// version string the detector intentionally left untouched (e.g.
		// "SAS 9.4.1.2") isn't then flagged here as unredacted PII.
		{name: "unredacted-ipv4", severity: SeverityHigh,
			pattern: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
			suppress: func(line string, start, end int) bool {
				return detect.LooksLikeVersionString(line, start)
			}},

		// Reuses detect.IsValidFQDN's TLD allowlist, the same way the real
		// FQDN detector does. Without it, this rule would also flag ordinary
		// filenames like "config.txt" or "settings.ini" -- a 2+ letter file
		// extension is syntactically indistinguishable from a TLD to a bare
		// shape regex. High findings need to stay rare on real sanitized
		// output for --strict to be usable.
		{name: "unredacted-fqdn", severity: SeverityHigh,
			find: func(line string) [][2]int { return findValidFQDNs(line, s.Ignore) }},

		{name: "email-shape", severity: SeverityHigh,
			pattern: regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)},

		{name: "mac-shape", severity: SeverityHigh,
			pattern: regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)},

		// Deliberately broad per the plan: catches bare words shaped like
		// environment-suffixed hostnames (e.g. "app-prod01", "db-uat") that
		// slipped past tokenization, at the cost of also matching ordinary
		// English words like "instead". Medium severity, not gated by
		// --strict, exactly because of that noise.
		{name: "hostname-shaped-bare-word", severity: SeverityMedium,
			pattern:  regexp.MustCompile(`(?i)\b[a-z][a-z0-9-]*-?(?:prod|dev|uat|qa|stage|stg|dr|test)[0-9]*\b`),
			suppress: suppressOwnTokenFragment},

		// Similarly broad: any letters-then-digits word, optionally with a
		// server-ish suffix. Will also match things like "log4j" or
		// "java8" -- expected noise, Medium only. suppressOwnTokenFragment
		// keeps it from matching "IPV4"/"IPV6" inside our own IPV4_NNN /
		// IPV6_NNN tokens.
		{name: "server-suffix-bare-word", severity: SeverityMedium,
			pattern:  regexp.MustCompile(`(?i)\b[a-z]+[0-9]+(?:-(?:srv|server|host|node|db|web|app|mq))?\b`),
			suppress: suppressOwnTokenFragment},

		{name: "long-random-near-credential-keyword", severity: SeverityMedium,
			find: findLongRandomNearCredentialKeyword},

		{name: "windows-path-with-username", severity: SeverityMedium,
			find: findWindowsPathWithNonTokenUsername},

		{name: "unix-path-with-username", severity: SeverityMedium,
			find: findUnixPathWithNonTokenUsername},
	}
	return s
}

// ScanLine returns every audit finding on a single already-sanitized line.
// file and lineNum are attached to each finding for the audit report.
func (s *Scanner) ScanLine(file string, lineNum int, line string) []Finding {
	var findings []Finding
	for _, r := range s.rules {
		var locs [][2]int
		if r.find != nil {
			locs = r.find(line)
		} else {
			for _, loc := range r.pattern.FindAllStringIndex(line, -1) {
				locs = append(locs, [2]int{loc[0], loc[1]})
			}
		}
		for _, loc := range locs {
			if r.suppress != nil && r.suppress(line, loc[0], loc[1]) {
				continue
			}
			findings = append(findings, Finding{
				File:     file,
				Line:     lineNum,
				Pattern:  r.name,
				Match:    line[loc[0]:loc[1]],
				Excerpt:  line,
				Severity: r.severity,
			})
		}
	}
	return findings
}

// fqdnCandidatePattern mirrors the FQDN detector's regex shape; candidates
// are then filtered through detect.IsValidFQDN's TLD allowlist by
// findValidFQDNs, the same two-step validation the real detector uses.
var fqdnCandidatePattern = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)

func findValidFQDNs(line string, ignore detect.IgnoreList) [][2]int {
	var out [][2]int
	for _, loc := range fqdnCandidatePattern.FindAllStringIndex(line, -1) {
		if detect.IsJVMSystemPropertyKey(line, loc[0]) {
			continue
		}
		candidate := line[loc[0]:loc[1]]
		if !detect.IsValidFQDN(candidate) {
			continue
		}
		if !ignore.Empty() && ignore.Matches(candidate) {
			continue
		}
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}

// longAlnumPattern and credentialKeywordPattern implement "20+ char
// alphanumeric string within 30 chars of a credential keyword" -- a proximity
// rule that doesn't fit the simple single-regex shape every other rule uses.
var (
	longAlnumPattern         = regexp.MustCompile(`\b[a-zA-Z0-9]{20,}\b`)
	credentialKeywordPattern = regexp.MustCompile(`(?i)password|token|secret|key|credential`)
)

const credentialProximityWindow = 30

func findLongRandomNearCredentialKeyword(line string) [][2]int {
	var out [][2]int
	for _, loc := range longAlnumPattern.FindAllStringIndex(line, -1) {
		start, end := loc[0], loc[1]
		ctxStart := start - credentialProximityWindow
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := end + credentialProximityWindow
		if ctxEnd > len(line) {
			ctxEnd = len(line)
		}
		if credentialKeywordPattern.MatchString(line[ctxStart:start]) || credentialKeywordPattern.MatchString(line[end:ctxEnd]) {
			out = append(out, [2]int{start, end})
		}
	}
	return out
}

// winPathUserPattern / unixPathUserPattern mirror the corresponding
// sanitization path detectors' shapes; the find functions only flag a match
// when the captured username segment is *not* already a CATEGORY_NNN token,
// since "the path detector already replaced this" is the success case, not
// a finding.
var (
	winPathUserPattern  = regexp.MustCompile(`C:\\Users\\([^\\]+)\\`)
	unixPathUserPattern = regexp.MustCompile(`/home/([^/]+)/`)
)

func findWindowsPathWithNonTokenUsername(line string) [][2]int {
	return findPathWithNonTokenUsername(line, winPathUserPattern)
}

func findUnixPathWithNonTokenUsername(line string) [][2]int {
	return findPathWithNonTokenUsername(line, unixPathUserPattern)
}

func findPathWithNonTokenUsername(line string, pattern *regexp.Regexp) [][2]int {
	var out [][2]int
	for _, loc := range pattern.FindAllStringSubmatchIndex(line, -1) {
		userStart, userEnd := loc[2], loc[3]
		if tokenShapePattern.MatchString(line[userStart:userEnd]) {
			continue
		}
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}
