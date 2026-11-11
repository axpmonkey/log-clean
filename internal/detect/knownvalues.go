package detect

import (
	"sort"
	"strings"
)

// KnownValue is an original value the run already knows is sensitive,
// together with the registry entry it belongs to. Text is what to look for
// in a line; Canonical is the registered value whose token replaces it (for
// a host's short name, Text is "pghost01" and Canonical is the FQDN
// "pghost01.corp.example.com", so both get the same token).
type KnownValue struct {
	Text      string
	Category  string
	Canonical string
}

// Minimum lengths for swept values: shorter strings match too much ordinary
// text to replace safely.
const (
	minSweepUserLength      = 3
	minSweepHostLabelLength = 4
)

// sweepStopwords are values never swept even when registered, because they
// are ordinary words in log text (a USER of "admin", the "support" label of
// support.example.com). Lowercase.
var sweepStopwords = toSet(
	// generic accounts / roles
	"admin", "administrator", "root", "user", "users", "guest", "system", "service", "services",
	"default", "public", "anonymous", "nobody", "everyone", "operator", "daemon", "test", "demo",
	// SAS / middleware words
	"sas", "sasadm", "saslogon", "sasdrive", "sasweb", "metadata", "compute", "workspace", "server",
	"servers", "tomcat", "apache", "httpd", "java", "postgres", "postgresql", "oracle", "activemq",
	"geode", "logon", "login", "logout", "auth", "oauth", "saml",
	// network / host words
	"host", "hosts", "localhost", "node", "nodes", "cluster", "master", "primary", "secondary",
	"backup", "proxy", "gateway", "router", "mail", "smtp", "imap", "ldap", "ldaps", "dns", "ntp",
	"www", "web", "app", "apps", "api", "portal", "docs", "support", "help", "status", "static",
	"cdn", "media", "files", "file", "download", "downloads", "update", "updates", "secure", "sso",
	"vpn", "remote", "access", "connect", "intranet", "internal", "corp", "local", "example",
	"prod", "production", "dev", "development", "stage", "staging", "uat", "data", "database",
	"cloud", "edge", "origin", "client", "clients", "office", "shared", "common", "config",
	// log vocabulary
	"info", "warn", "warning", "error", "debug", "trace", "fatal", "true", "false", "null", "none",
)

func toSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func sweepable(text string, minLen int) bool {
	if len(text) < minLen || sweepStopwords[strings.ToLower(text)] {
		return false
	}
	return strings.Trim(text, "0123456789.") != "" // not purely numeric
}

// SweepValues selects the known values the end-of-chain sweep replaces:
// every registered USER value and every registered HOST value, plus the
// first label of each multi-label HOST (the short name the same machine
// goes by elsewhere), minus short values and common words. hosts and users
// are in registry (token) order; on a collision the first entry wins, so the
// result is deterministic.
//
// A host's first label is only taken from names with three or more labels:
// in a two-label name ("acme.com") the first label is the organization's
// domain, not a machine.
func SweepValues(users, hosts []string) []KnownValue {
	var out []KnownValue
	seen := map[string]bool{}
	add := func(text, category, canonical string) {
		key := asciiLower(text)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, KnownValue{Text: text, Category: category, Canonical: canonical})
	}
	for _, h := range hosts {
		if strings.Contains(h, ".") || sweepable(h, minSweepHostLabelLength) {
			add(h, "HOST", h)
		}
	}
	for _, u := range users {
		if sweepable(u, minSweepUserLength) {
			add(u, "USER", u)
		}
	}
	for _, h := range hosts {
		labels := strings.Split(h, ".")
		if len(labels) >= 3 && sweepable(labels[0], minSweepHostLabelLength) {
			add(labels[0], "HOST", h)
		}
	}
	return out
}

// minAuditValueLength gates the non-USER/HOST values the audit looks for.
const minAuditValueLength = 4

// AuditValues selects the original values the audit's known-original-value
// rule searches sanitized output for: the sweep set (so the audit and the
// sweep agree on what must be gone -- a value the sweep deliberately skips,
// like a stopword, is not then reported) plus every value of every other
// category in the mapping (IPs, emails, DNs, URLs, UNC paths, domains, ...)
// matched exactly. byCategory holds each category's values in token order.
func AuditValues(byCategory map[string][]string) []KnownValue {
	out := SweepValues(byCategory["USER"], byCategory["HOST"])
	seen := map[string]bool{}
	for _, v := range out {
		seen[asciiLower(v.Text)] = true
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		if c != "USER" && c != "HOST" {
			cats = append(cats, c)
		}
	}
	sort.Strings(cats)
	for _, c := range cats {
		for _, v := range byCategory[c] {
			key := asciiLower(v)
			if seen[key] || !sweepable(v, minAuditValueLength) {
				continue
			}
			seen[key] = true
			out = append(out, KnownValue{Text: v, Category: c, Canonical: v})
		}
	}
	return out
}

// KnownValuesDetector replaces every occurrence of an already-known
// sensitive value: a value some detector found *somewhere* in the bundle is
// then removed *everywhere*, including in lines and files where no detector
// would have matched it on its own (e.g. "user jdoe logged in" when jdoe was
// found in /home/jdoe/). Matching is whole-word and case-insensitive.
//
// It is built between Pass 1 and Pass 2 from the complete registry and
// appended as the last detector in the chain, so it only ever fills gaps:
// every span an earlier detector claimed is left alone, and every value it
// emits is already registered, so Pass 2's Lookup always succeeds.
type KnownValuesDetector struct {
	// byLower maps an ASCII-lowercased value to its entry.
	byLower map[string]KnownValue
	// wordStartLens are the distinct lengths, longest first, of values that
	// begin with a word character; each is tried at every word start.
	wordStartLens []int
	// otherStart are lowercased values beginning with a non-word character
	// (e.g. a UNC path), found by substring search; longest first.
	otherStart []string
}

// NewKnownValuesDetector returns nil when values is empty. On a collision
// (same value ignoring case) the first entry wins, as in SweepValues.
//
// Matching is a hash lookup, not a regex: an alternation of thousands of
// case-insensitive values (one per user/host in a large bundle) gets no
// literal-prefix help from RE2 and made Pass 2 more than 20x slower. Here the
// line is lowercased once and, at each word start, each distinct value length
// is checked against a set -- whole-word, case-insensitive, longest-first.
func NewKnownValuesDetector(values []KnownValue) *KnownValuesDetector {
	if len(values) == 0 {
		return nil
	}
	d := &KnownValuesDetector{byLower: make(map[string]KnownValue, len(values))}
	lens := map[int]bool{}
	for _, v := range values {
		key := asciiLower(v.Text)
		if _, dup := d.byLower[key]; dup || key == "" {
			continue
		}
		d.byLower[key] = v
		if isWordByte(key[0]) {
			lens[len(key)] = true
		} else {
			d.otherStart = append(d.otherStart, key)
		}
	}
	for l := range lens {
		d.wordStartLens = append(d.wordStartLens, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(d.wordStartLens)))
	sort.SliceStable(d.otherStart, func(i, j int) bool { return len(d.otherStart[i]) > len(d.otherStart[j]) })
	return d
}

// asciiLower lowercases ASCII letters only, so byte offsets in the result
// line up with the original (strings.ToLower can change byte lengths).
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// endsOnBoundary reports whether a value ending at line[e] (exclusive) ends
// on a word boundary: \b semantics when its last byte is a word character,
// no constraint otherwise.
func endsOnBoundary(line string, e int) bool {
	return !isWordByte(line[e-1]) || e == len(line) || !isWordByte(line[e])
}

func (*KnownValuesDetector) Name() string { return "known-values" }

func (d *KnownValuesDetector) Detect(line string) []Match {
	lower := asciiLower(line)
	var matches []Match
	emit := func(s, e int, v KnownValue) {
		matches = append(matches, Match{Span: Span{Start: s, End: e}, Value: v.Canonical, Category: v.Category})
	}
	for i := 0; i < len(lower); i++ {
		if !isWordByte(lower[i]) || (i > 0 && isWordByte(lower[i-1])) {
			continue
		}
		for _, l := range d.wordStartLens {
			e := i + l
			if e > len(lower) {
				continue
			}
			if v, ok := d.byLower[lower[i:e]]; ok && endsOnBoundary(lower, e) {
				emit(i, e, v)
				i = e - 1
				break
			}
		}
	}
	for _, key := range d.otherStart {
		for from := 0; ; {
			k := strings.Index(lower[from:], key)
			if k < 0 {
				break
			}
			s, e := from+k, from+k+len(key)
			if endsOnBoundary(lower, e) {
				emit(s, e, d.byLower[key])
			}
			from = e
		}
	}
	return matches
}

// FindAll returns the spans of every known value in line, for the audit
// scanner's known-original-value rule. Safe to call on a nil detector.
func (d *KnownValuesDetector) FindAll(line string) [][2]int {
	if d == nil {
		return nil
	}
	var out [][2]int
	for _, m := range d.Detect(line) {
		out = append(out, [2]int{m.Span.Start, m.Span.End})
	}
	return out
}
