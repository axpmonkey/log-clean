package detect

import "strings"

// Cheap byte checks that let the pipeline skip a detector's regexes on lines
// that can't contain a match (see Prefilter). Each is conservative: it
// returns false only when the detector's patterns require something the line
// lacks. TestPrefiltersAreConservative checks this against every golden
// fixture line.

func (UUIDDetector) MightMatch(line string) bool { return strings.Count(line, "-") >= 4 }
func (DNDetector) MightMatch(line string) bool {
	return strings.IndexByte(line, '=') >= 0 && strings.IndexByte(line, ',') >= 0
}
func (EmailDetector) MightMatch(line string) bool { return strings.IndexByte(line, '@') >= 0 }
func (URLDetector) MightMatch(line string) bool   { return strings.Contains(line, "://") }
func (FQDNDetector) MightMatch(line string) bool  { return strings.IndexByte(line, '.') >= 0 }
func (IPv4Detector) MightMatch(line string) bool  { return strings.Count(line, ".") >= 3 }
func (IPv6Detector) MightMatch(line string) bool  { return strings.Count(line, ":") >= 2 }
func (MACDetector) MightMatch(line string) bool {
	return strings.Count(line, ":") >= 5 || strings.Count(line, "-") >= 5
}
func (UNCDetector) MightMatch(line string) bool        { return strings.Contains(line, `\\`) }
func (KerberosDetector) MightMatch(line string) bool   { return strings.IndexByte(line, '@') >= 0 }
func (DomainUserDetector) MightMatch(line string) bool { return strings.IndexByte(line, '\\') >= 0 }
func (WindowsUserPathDetector) MightMatch(line string) bool {
	return strings.IndexByte(line, '\\') >= 0
}
func (BareUserDetector) MightMatch(line string) bool {
	return strings.Contains(asciiLower(line), "user")
}
func (UnixUserPathDetector) MightMatch(line string) bool {
	return strings.Contains(line, "/home/") || strings.Contains(line, "/Users/")
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
