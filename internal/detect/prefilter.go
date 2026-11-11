package detect

import "strings"

// Cheap byte checks that let the pipeline skip a detector's regexes on lines
// that can't contain a match (see Prefilter). Each is conservative: it
// returns false only when the detector's patterns require something the line
// lacks. TestPrefiltersAreConservative checks this against every golden
// fixture line.

func (UUIDDetector) MightMatch(line string) bool { return strings.Count(line, "-") >= 4 }

// A DN must end in ",<attr>=" with a well-known attribute (dnPattern's
// final component). Checking for exactly that keeps the regex off the many
// SAS log lines whose only comma is in a log4j timestamp ("12:00:00,123").
func (DNDetector) MightMatch(line string) bool {
	if strings.IndexByte(line, '=') < 0 {
		return false
	}
	for i := 0; i < len(line); i++ {
		if line[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(line) && isRE2Space(line[j]) {
			j++
		}
		k := j
		for k < len(line) && (isASCIILetter(line[k]) || line[k] >= 0x80) {
			k++
		}
		if k < len(line) && line[k] == '=' && (dnFinalAttrs[asciiLower(line[j:k])] || hasNonASCII(line[j:k])) {
			return true
		}
	}
	return false
}

// dnFinalAttrs is dnAttr, lowercased.
var dnFinalAttrs = toSet("cn", "ou", "dc", "uid", "o", "l", "st", "c")

// hasParamKey reports whether some '=' in lower (an ASCII-lowercased line)
// is directly preceded by a whole word in keys -- the "\b<name>=" and
// "[?&;]<name>=" shapes the query-parameter credential patterns require.
// A word containing non-ASCII bytes counts as a possible key, since (?i)
// also folds a few non-ASCII letters (e.g. the Kelvin sign) to ASCII.
func hasParamKey(lower string, keys map[string]bool) bool {
	for i := strings.IndexByte(lower, '='); i >= 0; {
		j := i
		for j > 0 && (isRE2WordChar(lower[j-1]) || lower[j-1] >= 0x80) {
			j--
		}
		if j < i && (keys[lower[j:i]] || hasNonASCII(lower[j:i])) {
			return true
		}
		next := strings.IndexByte(lower[i+1:], '=')
		if next < 0 {
			break
		}
		i += 1 + next
	}
	return false
}

func isASCIILetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// isRE2WordChar is RE2's \w (and so what \b tests): ASCII only.
func isRE2WordChar(c byte) bool { return isASCIILetter(c) || c >= '0' && c <= '9' || c == '_' }

// isRE2Space is RE2's \s: ASCII only.
func isRE2Space(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
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
	l := asciiLower(line)
	return strings.Contains(l, "user") || strings.Contains(l, "uid") || hasNonASCII(line)
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
