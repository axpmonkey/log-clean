package audit

import "regexp"

// Hand-written scanners for the broad (?i) word-shape audit rules, which run
// on most lines. Same contract as internal/detect/scanners.go: each returns
// exactly what FindAllStringIndex returns for the regex it replaces, the
// regexes stay here as the reference, and TestAuditScannersMatchRegexps /
// FuzzAuditScanners compare the two. (?i) also folds a few non-ASCII letters
// (the Kelvin sign, long s) onto ASCII ones, so both fall back to the regex
// on a line with any non-ASCII byte.

// hostnameShapedPattern is the hostname-shaped-bare-word rule.
var hostnameShapedPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9-]*-?(?:prod|dev|uat|qa|stage|stg|dr|test)[0-9]*\b`)

// serverSuffixPattern is the server-suffix-bare-word rule.
var serverSuffixPattern = regexp.MustCompile(`(?i)\b[a-z]+[0-9]+(?:-(?:srv|server|host|node|db|web|app|mq))?\b`)

var (
	envKeywords    = []string{"prod", "dev", "uat", "qa", "stage", "stg", "dr", "test"}
	serverSuffixes = []string{"srv", "server", "host", "node", "db", "web", "app", "mq"}
)

func isWordByte(c byte) bool { return isASCIILetter(c) || isDigit(c) || c == '_' }

// hasFoldPrefix reports whether s[i:] starts with lowercase-ASCII word w,
// ignoring ASCII case.
func hasFoldPrefix(s string, i int, w string) bool {
	if len(s)-i < len(w) {
		return false
	}
	for k := 0; k < len(w); k++ {
		if s[i+k]|0x20 != w[k] || !isASCIILetter(s[i+k]) {
			return false
		}
	}
	return true
}

// findWordShapes runs match at every possible start of a \b[a-z] pattern
// (an ASCII letter not preceded by a word byte), leftmost-first and
// non-overlapping like FindAllStringIndex.
func findWordShapes(line string, match func(line string, i int) (int, bool)) [][2]int {
	var out [][2]int
	for i := 0; i < len(line); i++ {
		if !isASCIILetter(line[i]) || i > 0 && isWordByte(line[i-1]) {
			continue
		}
		if end, ok := match(line, i); ok {
			out = append(out, [2]int{i, end})
			i = end - 1
		}
	}
	return out
}

func regexLocs(re *regexp.Regexp, line string) [][2]int {
	var out [][2]int
	for _, l := range re.FindAllStringIndex(line, -1) {
		out = append(out, [2]int{l[0], l[1]})
	}
	return out
}

// findHostnameShapedWords scans for hostnameShapedPattern.
func findHostnameShapedWords(line string) [][2]int {
	if hasNonASCII(line) {
		return regexLocs(hostnameShapedPattern, line)
	}
	return findWordShapes(line, matchHostnameShaped)
}

// matchHostnameShaped follows the regex's backtracking order: the greedy
// [a-z0-9-]* (which can only cover the [a-z0-9-] run after the first
// letter) gives back one byte at a time, -? first tries taking a '-', then
// a keyword (at most one can match at a position) and the digit run, which
// must be taken whole for \b to hold after it.
func matchHostnameShaped(line string, i int) (int, bool) {
	run := i + 1
	for run < len(line) && (isASCIILetter(line[run]) || isDigit(line[run]) || line[run] == '-') {
		run++
	}
	for j := run; j > i; j-- {
		for _, dash := range [2]bool{true, false} {
			p := j
			if dash {
				if j == len(line) || line[j] != '-' {
					continue
				}
				p++
			}
			for _, kw := range envKeywords {
				if !hasFoldPrefix(line, p, kw) {
					continue
				}
				x := p + len(kw)
				for x < len(line) && isDigit(line[x]) {
					x++
				}
				if x == len(line) || !isWordByte(line[x]) {
					return x, true
				}
			}
		}
	}
	return 0, false
}

// findServerSuffixWords scans for serverSuffixPattern.
func findServerSuffixWords(line string) [][2]int {
	if hasNonASCII(line) {
		return regexLocs(serverSuffixPattern, line)
	}
	return findWordShapes(line, matchServerSuffix)
}

// matchServerSuffix: [a-z]+ must take the whole letter run (a digit has to
// follow it) and [0-9]+ the whole digit run (\b, or '-', has to follow);
// then the optional -suffix is tried before going without it.
func matchServerSuffix(line string, i int) (int, bool) {
	a := i
	for a < len(line) && isASCIILetter(line[a]) {
		a++
	}
	b := a
	for b < len(line) && isDigit(line[b]) {
		b++
	}
	if b == a {
		return 0, false
	}
	if b < len(line) && line[b] == '-' {
		for _, suf := range serverSuffixes {
			if e := b + 1 + len(suf); hasFoldPrefix(line, b+1, suf) && (e == len(line) || !isWordByte(line[e])) {
				return e, true
			}
		}
	}
	if b == len(line) || !isWordByte(line[b]) {
		return b, true
	}
	return 0, false
}
