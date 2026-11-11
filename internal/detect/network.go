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

// ipv4VersionKeyword matches a version/product keyword that is the token
// *immediately* preceding a dotted-quad-shaped match ("SAS 9.4.8.0",
// "version 1.2.3.4", "release: 9.4.1.2"). It is anchored to the end of the
// preceding text on purpose: in SAS logs "SAS" appears almost everywhere, so
// a keyword merely somewhere nearby ("Connecting to SAS server at
// 10.20.30.40") says nothing about the number that follows.
var ipv4VersionKeyword = regexp.MustCompile(`(?i)\b(?:v|version|release|sas)\s*[:=]?\s*$`)

// ipv4FollowedByPort matches ":<port>" right after a dotted quad. A version
// string never carries a port; "SAS Metadata 10.20.30.41:8561" is an address.
var ipv4FollowedByPort = regexp.MustCompile(`^:\d`)

// privateIPv4Ranges are the RFC 1918 blocks. Real SAS/Java version strings
// never fall in them, while internal server addresses almost always do, so a
// private-range dotted quad is always treated as an address even right after
// a version keyword ("release 10.20.30.42 is the gateway"). Getting this
// wrong over-redacts a version, which is the safe direction.
var privateIPv4Ranges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// LooksLikeVersionString reports whether the dotted-quad-shaped match
// line[start:end] is a version number rather than a real IPv4 address. It is
// a version only when all of these hold:
//   - a version keyword (v, version, release, sas) is the immediately
//     preceding token;
//   - it is not followed by ":<port>";
//   - it is not in a private (RFC 1918) range.
//
// Exported so the audit scanner (internal/audit) applies the identical rule:
// if the audit used its own heuristic, it would flag the version strings this
// detector intentionally left alone as "unredacted PII".
func LooksLikeVersionString(line string, start, end int) bool {
	if !hasVersionKeywordSuffix(line[:start]) { // ipv4VersionKeyword
		return false
	}
	if end+1 < len(line) && line[end] == ':' && isDigitByte(line[end+1]) { // ipv4FollowedByPort
		return false
	}
	return !IPInSkipRanges(line[start:end], privateIPv4Ranges)
}

// IPv4Detector tokenizes dotted-quad IPv4 addresses. Its zero value is
// valid (skips nothing); NewIPv4Detector attaches skip ranges from the
// config's detectors.ipv4.skip_ranges.
type IPv4Detector struct {
	// Classify emits IPV4_PRIV (RFC 1918, loopback, link-local, CGNAT) or
	// IPV4_PUB instead of IPV4, so sanitized output still shows whether
	// traffic leaves the network (--ip-class).
	Classify bool

	// skipRanges are CIDR blocks whose addresses are deliberately left
	// untokenized (e.g. non-sensitive internal ranges). Nil means skip
	// nothing.
	skipRanges []netip.Prefix
}

// NewIPv4Detector returns an IPv4Detector that leaves any address falling in
// one of skipRanges untokenized.
func NewIPv4Detector(skipRanges []netip.Prefix) IPv4Detector {
	return IPv4Detector{skipRanges: skipRanges}
}

func (IPv4Detector) Name() string { return "ipv4" }

func (d IPv4Detector) Detect(line string) []Match {
	locs := findDottedQuads(line, true) // ipv4Pattern
	if locs == nil {
		return nil
	}
	var matches []Match
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		if LooksLikeVersionString(line, start, end) {
			continue
		}
		if IPInSkipRanges(line[start:end], d.skipRanges) {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: start, End: end},
			Value:    line[start:end],
			Category: d.category(line[start:end]),
		})
	}
	return matches
}

// nonPublicIPv4Ranges are the IPv4 blocks --ip-class reports as private.
var nonPublicIPv4Ranges = append([]netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT
}, privateIPv4Ranges...)

// category returns the token category for the IPv4 address ip.
func (d IPv4Detector) category(ip string) string {
	if !d.Classify {
		return "IPV4"
	}
	if IPInSkipRanges(ip, nonPublicIPv4Ranges) {
		return "IPV4_PRIV"
	}
	return "IPV4_PUB"
}

// IPInSkipRanges reports whether ipStr parses as an address inside one of
// ranges. Exported so the audit scanner (internal/audit) can apply the same
// suppression -- without it, an IP the detector intentionally left untokenized
// (per detectors.ipv4.skip_ranges) would then be flagged by the audit pass's
// unredacted-ipv4 rule as residual PII, a false positive that would also trip
// --strict.
func IPInSkipRanges(ipStr string, ranges []netip.Prefix) bool {
	if len(ranges) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if r.Contains(addr) {
			return true
		}
	}
	return false
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
	for _, loc := range findIPv6Candidates(line) { // ipv6Core
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
		if IsJVMSystemPropertyKey(line, loc[0]) {
			continue
		}
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

// IsJVMSystemPropertyKey reports whether the FQDN-shaped candidate starting
// at byte offset start in line is actually the key half of a JVM system
// property (e.g. "-Dcatalina.home=...", "-Djava.net.preferIPv4Stack=true",
// "-Dcom.sun.management.jmxremote"). Dotted Java package/property names use
// the same ordinary-English vocabulary as several pseudo-TLDs in
// allowedTLDs (home, net, io, info, name, ...), so without this guard they
// get misdetected as hostnames. The "-D" flag prefix is the reliable
// syntactic signal here -- it doesn't require enumerating every JVM/vendor
// package prefix (com.sun, com.sas, org.apache, javax, ...), which would
// always be an incomplete list.
//
// Note the candidate itself starts with the "D", not after it: "D" and the
// following letter are both word characters, so fqdnPattern's leading \b
// anchors between "-" and "D", not between "D" and the property name.
// Exported so the audit scanner (internal/audit) can apply the identical
// guard -- without it, the audit pass's unredacted-fqdn rule would flag the
// very JVM property keys this detector intentionally chose not to
// tokenize as "unredacted PII", which would be a false positive.
func IsJVMSystemPropertyKey(line string, start int) bool {
	return start >= 1 && line[start-1] == '-' && start < len(line) && line[start] == 'D'
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

// URLDetector tokenizes URLs in one of two modes:
//
//   - HostOnly (the default chain's mode, --url-mode=host): only the
//     sensitive parts are replaced -- the userinfo (user -> USER_NNN,
//     password -> SECRET_REDACTED) and the host (HOST_NNN). Scheme, port,
//     path and parameter names stay, because they are what troubleshooting
//     needs: "http://HOST_003:8080", "jdbc:postgresql://HOST_002:9432/db".
//     An IP-address host is left for the IPv4/IPv6 detectors that run next
//     (so skip ranges and IPV4/IPV6 categories still apply), and "localhost"
//     is left alone. Path segments holding PII are handled by the user-path
//     detectors and the known-values sweep; credential parameter values were
//     already redacted by CredentialsDetector.
//   - Whole (zero value, --url-mode=whole): the entire URL becomes one
//     URL_NNN token, the pre-0.2 behavior.
type URLDetector struct {
	HostOnly bool
}

func (URLDetector) Name() string { return "url" }

func (d URLDetector) Detect(line string) []Match {
	locs := urlPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	if d.HostOnly {
		var matches []Match
		for _, loc := range locs {
			matches = append(matches, urlAuthorityMatches(line, loc[0], loc[1])...)
		}
		return matches
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

// urlAuthorityEnd matches the characters that end a URL's authority
// component (";" covers jdbc:sqlserver://host:1433;databaseName=x).
const urlAuthorityEnd = "/?#;"

// urlAuthorityMatches returns the userinfo and host matches for the URL at
// line[s:e] (HostOnly mode).
func urlAuthorityMatches(line string, s, e int) []Match {
	idx := strings.Index(line[s:e], "://")
	if idx < 0 {
		return nil
	}
	a := s + idx + 3
	ae := e
	if i := strings.IndexAny(line[a:e], urlAuthorityEnd); i >= 0 {
		ae = a + i
	}

	var matches []Match
	h := a
	if at := strings.LastIndexByte(line[a:ae], '@'); at >= 0 {
		us, ue := a, a+at
		if c := strings.IndexByte(line[us:ue], ':'); c >= 0 {
			if ue > us+c+1 {
				matches = append(matches, Match{Span: Span{Start: us + c + 1, End: ue}, Value: line[us+c+1 : ue], Redact: true})
			}
			ue = us + c
		}
		if ue > us {
			matches = append(matches, Match{Span: Span{Start: us, End: ue}, Value: line[us:ue], Category: "USER"})
		}
		h = a + at + 1
	}
	if h >= ae || line[h] == '[' {
		return matches // empty host, or a bracketed IPv6 literal (IPv6 detector)
	}
	he := ae
	if c := strings.IndexByte(line[h:ae], ':'); c >= 0 {
		he = h + c
	}
	host := line[h:he]
	if host == "" || strings.EqualFold(host, "localhost") {
		return matches
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return matches // IP host: the IPv4/IPv6 detectors handle it
	}
	return append(matches, Match{Span: Span{Start: h, End: he}, Value: host, Category: "HOST"})
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
