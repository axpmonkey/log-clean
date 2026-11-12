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
	// prefixLens maps the first two bytes of the values that begin with a
	// word character (and are 2+ bytes long) to their distinct lengths,
	// longest first; prefixSeen is a bitset of its keys. At a word start
	// only the lengths of values sharing the next two bytes are tried, so
	// most word starts cost one bit test instead of a hash per length.
	prefixLens map[uint16][]int
	prefixSeen [1 << 16 / 64]uint64
	// oneByte marks single-byte word values (tried last: shortest).
	oneByte [256]bool
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
	d := &KnownValuesDetector{byLower: make(map[string]KnownValue, len(values)), prefixLens: map[uint16][]int{}}
	lens := map[uint16]map[int]bool{}
	for _, v := range values {
		key := asciiLower(v.Text)
		if _, dup := d.byLower[key]; dup || key == "" {
			continue
		}
		d.byLower[key] = v
		switch {
		case !isWordByte(key[0]):
			d.otherStart = append(d.otherStart, key)
		case len(key) == 1:
			d.oneByte[key[0]] = true
		default:
			p := prefix2(key, 0)
			if lens[p] == nil {
				lens[p] = map[int]bool{}
			}
			lens[p][len(key)] = true
		}
	}
	for p, set := range lens {
		ls := make([]int, 0, len(set))
		for l := range set {
			ls = append(ls, l)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ls)))
		d.prefixLens[p] = ls
		d.prefixSeen[p/64] |= 1 << (p % 64)
	}
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
		if e, ok := d.matchWordStart(lower, i); ok {
			emit(i, e, d.byLower[lower[i:e]])
			i = e - 1
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

func prefix2(s string, i int) uint16 { return uint16(s[i])<<8 | uint16(s[i+1]) }

// matchWordStart returns the end of the longest known value starting at
// word start i of lower that ends on a word boundary.
func (d *KnownValuesDetector) matchWordStart(lower string, i int) (int, bool) {
	if i+1 < len(lower) {
		if p := prefix2(lower, i); d.prefixSeen[p/64]&(1<<(p%64)) != 0 {
			for _, l := range d.prefixLens[p] {
				e := i + l
				if e > len(lower) {
					continue
				}
				if _, ok := d.byLower[lower[i:e]]; ok && endsOnBoundary(lower, e) {
					return e, true
				}
			}
		}
	}
	if d.oneByte[lower[i]] && endsOnBoundary(lower, i+1) {
		return i + 1, true
	}
	return 0, false
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

// sasInternalAccounts are the internal accounts every SAS 9.4 deployment
// creates, authenticated by the metadata server and written "<name>@saspw".
// They are the same at every site and identify no person or customer, and
// they matter for root-cause analysis (which identity a server connected
// as), so they are left readable rather than pseudonymized. Lowercase.
var sasInternalAccounts = toSet("sasadm", "sastrust", "sasevs", "webanon")

const sasInternalDomain = "@saspw"

// IsSASInternalAccount reports whether line[start:end] is one of the SAS
// internal accounts in its "<name>@saspw" form (case-insensitive): either
// the span is the whole "<name>@saspw", or it is "<name>" directly followed
// by "@saspw" (detectors such as bare-user stop a username at the '@').
// The same name anywhere else -- without the @saspw suffix -- is not
// exempt.
func IsSASInternalAccount(line string, start, end int) bool {
	v := asciiLower(line[start:end])
	if name, ok := strings.CutSuffix(v, sasInternalDomain); ok {
		return sasInternalAccounts[name]
	}
	if !sasInternalAccounts[v] || end+len(sasInternalDomain) > len(line) {
		return false
	}
	if !strings.EqualFold(line[end:end+len(sasInternalDomain)], sasInternalDomain) {
		return false
	}
	// "@saspw" must end there: "sasadm@saspwx" is some other domain.
	after := end + len(sasInternalDomain)
	return after == len(line) || !isRE2WordChar(line[after]) && line[after] != '.' && line[after] != '-'
}
