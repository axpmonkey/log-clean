package detect

import (
	"net/netip"
	"regexp"
	"strings"
)

// ---- IPv4 ----------------------------------------------------------------

// ipv4Pattern matches dotted-quad addresses with octet ranges validated
// directly in the regex (each alternative covers 0-199, 200-249, 250-255)
// rather than matching any \d{1,3} and validating afterward.
var ipv4Pattern = regexp.MustCompile(`\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

// ipv4VersionContext matches the version/product keywords that, when found
// in the 20 characters preceding a dotted-quad-shaped match, mean it's
// almost certainly a version string (e.g. "SAS 9.4.1.2", "version 9.4.1.2")
// rather than a real IP address (plan Decision 6 / IPv4 detector spec).
var ipv4VersionContext = regexp.MustCompile(`(?i)\b(v|version|release|sas)\b`)

const versionContextWindow = 20

// LooksLikeVersionString reports whether the text immediately preceding a
// dotted-quad-shaped match at byte offset start in line suggests it's a
// version number rather than a real IPv4 address. Exported so the audit
// scanner (internal/audit) can apply the identical suppression rule -- if
// the audit pass used its own separate heuristic, it would flag the very
// version strings this detector intentionally chose not to tokenize as
// "unredacted PII", which would be a false positive, not real residual risk.
func LooksLikeVersionString(line string, start int) bool {
	ctxStart := start - versionContextWindow
	if ctxStart < 0 {
		ctxStart = 0
	}
	return ipv4VersionContext.MatchString(line[ctxStart:start])
}

type IPv4Detector struct{}

func (IPv4Detector) Name() string { return "ipv4" }

func (IPv4Detector) Detect(line string) []Match {
	locs := ipv4Pattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	var matches []Match
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if LooksLikeVersionString(line, start) {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: start, End: end},
			Value:    line[start:end],
			Category: "IPV4",
		})
	}
	return matches
}

// ---- IPv6 ------------------------------------------------------------

// ipv6Core matches a maximal run of characters that could plausibly be part
// of an IPv6 address (hex digits, colons, and dots for the IPv4-mapped
// form). IPv6 syntax is notoriously hard to validate with regex alone, so
// this is deliberately loose -- it only finds candidate spans. Every
// candidate is then validated with net/netip.ParseAddr, which is the actual
// source of truth for whether it's a real address.
var ipv6Core = regexp.MustCompile(`[0-9a-fA-F:.]+`)

// ipv6Zone matches an interface zone suffix like "%eth0".
var ipv6Zone = regexp.MustCompile(`^%[0-9a-zA-Z]+`)

type IPv6Detector struct{}

func (IPv6Detector) Name() string { return "ipv6" }

func (IPv6Detector) Detect(line string) []Match {
	var matches []Match
	for _, loc := range ipv6Core.FindAllStringIndex(line, -1) {
		start, end := loc[0], loc[1]

		// A real IPv6 address needs at least two colons (even the shortest
		// compressed forms like "::1" have two). This cheaply rejects plain
		// decimal numbers and IPv4 addresses, which this char class also
		// matches, before paying for a ParseAddr call.
		if strings.Count(line[start:end], ":") < 2 {
			continue
		}

		if zoneLoc := ipv6Zone.FindStringIndex(line[end:]); zoneLoc != nil {
			end += zoneLoc[1]
		}

		// Trim a trailing '.' that's more likely end-of-sentence punctuation
		// than part of the address (only relevant for the IPv4-mapped form,
		// which is the only IPv6 shape containing dots).
		for end > start && line[end-1] == '.' {
			end--
		}

		candidate := line[start:end]
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is6() {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: start, End: end},
			Value:    candidate,
			Category: "IPV6",
		})
	}
	return matches
}

// ---- FQDN ------------------------------------------------------------

// fqdnPattern matches dot-separated DNS label sequences. Label syntax
// (alphanumeric, internal hyphens, 1-63 chars) is enforced by the regex;
// TLD plausibility is checked separately in IsValidFQDN, since regex alone
// can't express "is the last label a real top-level domain."
var fqdnPattern = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)

// allowedTLDs gates which dotted names get treated as real hostnames. This
// is what keeps "app.log" or "server.xml" (and incidentally,
// "org.apache.foo.Bar"-style fully-qualified Java class names seen in stack
// traces, whose last segment is a class name, not a TLD) from being
// misdetected as FQDNs: their final label isn't a real or pseudo TLD.
var allowedTLDs = buildAllowedTLDs()

func buildAllowedTLDs() map[string]bool {
	tlds := []string{
		// ~30 common public TLDs.
		"com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name",
		"pro", "co", "io", "ai", "dev", "app", "cloud", "tech", "online", "site",
		"xyz", "me", "tv", "us", "uk", "ca", "de", "fr", "jp", "cn", "au", "eu",
		// Internal / pseudo-TLDs commonly seen in corporate logs.
		"local", "internal", "corp", "lan", "intra", "home", "arpa",
		"localdomain", "priv", "private",
	}
	m := make(map[string]bool, len(tlds))
	for _, t := range tlds {
		m[t] = true
	}
	return m
}

const maxFQDNLength = 253
const maxLabelLength = 63

// FQDNDetector validates candidate matches against allowedTLDs by default.
// Use NewFQDNDetectorWithExtraTLDs to additionally accept a profile's
// extra_internal_tlds (e.g. a customer's own internal pseudo-TLD).
type FQDNDetector struct {
	extraTLDs map[string]bool
}

// NewFQDNDetectorWithExtraTLDs returns an FQDNDetector that also accepts the
// given TLDs (case-insensitive) on top of the built-in allowedTLDs list.
func NewFQDNDetectorWithExtraTLDs(extra []string) FQDNDetector {
	if len(extra) == 0 {
		return FQDNDetector{}
	}
	m := make(map[string]bool, len(extra))
	for _, t := range extra {
		m[strings.ToLower(t)] = true
	}
	return FQDNDetector{extraTLDs: m}
}

func (FQDNDetector) Name() string { return "fqdn" }

func (d FQDNDetector) Detect(line string) []Match {
	locs := fqdnPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	var matches []Match
	for _, loc := range locs {
		candidate := line[loc[0]:loc[1]]
		if !d.isValid(candidate) {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: loc[1]},
			Value:    candidate,
			Category: "HOST",
		})
	}
	return matches
}

func (d FQDNDetector) isValid(s string) bool {
	tld, ok := fqdnShapeAndTLD(s)
	if !ok {
		return false
	}
	return allowedTLDs[tld] || d.extraTLDs[tld]
}

// IsValidFQDN reports whether s is a plausible FQDN: total/label length
// limits and a rightmost label that's a real or pseudo TLD (see
// allowedTLDs). Exported so the audit scanner (internal/audit) can apply the
// identical check -- without it, the audit pass's unredacted-fqdn rule would
// flag ordinary filenames like "config.txt" or "settings.ini" as residual
// hostnames, since ".txt"/".ini" are syntactically indistinguishable from a
// 2+ letter TLD to a regex alone.
func IsValidFQDN(s string) bool {
	tld, ok := fqdnShapeAndTLD(s)
	return ok && allowedTLDs[tld]
}

// fqdnShapeAndTLD validates everything about s except whether its rightmost
// label is an acceptable TLD, returning that label (lowercased) so callers
// can check it against whichever TLD set applies (the built-in list, a
// profile's extra TLDs, or both).
func fqdnShapeAndTLD(s string) (tld string, ok bool) {
	if len(s) > maxFQDNLength {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > maxLabelLength {
			return "", false
		}
	}
	return strings.ToLower(labels[len(labels)-1]), true
}

// ---- MAC address -------------------------------------------------------

// macPattern matches six colon- or hyphen-separated hex octet pairs. Note
// the separator is matched independently per group, so a mixed-separator
// string like "00:1A-2B:3C-4D:5E" will still match -- a known, accepted
// false-positive surface per the plan's literal pattern spec.
var macPattern = regexp.MustCompile(`\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)

type MACDetector struct{}

func (MACDetector) Name() string { return "mac" }

func (MACDetector) Detect(line string) []Match {
	locs := macPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: loc[1]},
			Value:    line[loc[0]:loc[1]],
			Category: "MAC",
		})
	}
	return matches
}

// ---- URL / URI ---------------------------------------------------------

// urlPattern matches a scheme (including the SAS/middleware-relevant ones:
// JDBC, ActiveMQ transports, LDAP) followed by "://" and everything up to
// the next whitespace or delimiter character that's unlikely to be part of
// a URL in log text (quotes, angle brackets, trailing punctuation).
var urlPattern = regexp.MustCompile(`(?:https?|ftps?|sftp|jdbc:[a-z]+|tcp|ssl|nio|amqps?|mqtt|ldaps?)://[^\s<>"',;)]+`)

// urlHost matches everything up to the first ':', '/', or '?' -- i.e. the
// host[:port] boundary of a URL's authority component.
var urlHost = regexp.MustCompile(`^[^:/?]+`)

type URLDetector struct{}

func (URLDetector) Name() string { return "url" }

func (URLDetector) Detect(line string) []Match {
	locs := urlPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: loc[1]},
			Value:    line[loc[0]:loc[1]],
			Category: "URL",
		})
	}
	return matches
}

// EmbeddedHost extracts the host portion of a matched URL value, e.g.
// "https://jdoe:secret@db-prod-01.acme.internal:5432/path" ->
// "db-prod-01.acme.internal". It returns ok=false if urlValue has no "://"
// or no host-shaped text follows it.
//
// Called by pipeline.ScanLine (Milestone 5's cross-detector consistency
// work) to register the embedded host into the HOST category, so it shares
// a token with the same hostname found standalone elsewhere in the bundle.
func EmbeddedHost(urlValue string) (host string, ok bool) {
	idx := strings.Index(urlValue, "://")
	if idx < 0 {
		return "", false
	}
	rest := urlValue[idx+3:]
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:] // strip "user:pass@"
	}
	host = urlHost.FindString(rest)
	if host == "" {
		return "", false
	}
	return host, true
}
