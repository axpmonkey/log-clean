package detect

import "strings"

// Hand-written scanners for the regexes that run on nearly every log line.
// Go's regexp engine has no literal prefix to search for in patterns such as
// `\b\d{1,3}\.` and so tries a match at every byte; these loops do the same
// job in a single cheap pass.
//
// Each scanner returns exactly what FindAllStringIndex (or, for the
// parameter scanners, the value group of FindAllStringSubmatchIndex) returns
// for the regex it replaces -- same spans, same leftmost-first,
// non-overlapping order. The regexes stay alongside them as the reference,
// and TestScannersMatchRegexps checks the two against each other on random
// input. Change one, change both.
//
// RE2's \b, \w, \d and \s are ASCII-only, so a byte >= 0x80 is never a word
// character, digit or space here either. Case-insensitive patterns are the
// exception: (?i) also folds a few non-ASCII letters (the Kelvin sign, long
// s) onto ASCII ones, so the scanners for those fall back to the regex on any
// line containing a non-ASCII byte.

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isHexByte(c byte) bool {
	return isDigitByte(c) || c|0x20 >= 'a' && c|0x20 <= 'f'
}

// wordBoundaryBefore reports whether RE2's \b holds at i, given line[i] is a
// word character.
func wordBoundaryBefore(line string, i int) bool {
	return i == 0 || !isRE2WordChar(line[i-1])
}

// wordBoundaryAfter reports whether RE2's \b holds at end, given line[end-1]
// is a word character.
func wordBoundaryAfter(line string, end int) bool {
	return end == len(line) || !isRE2WordChar(line[end])
}

// digitRunEnd returns the end of the run of ASCII digits starting at i.
func digitRunEnd(line string, i int) int {
	for i < len(line) && isDigitByte(line[i]) {
		i++
	}
	return i
}

// findDottedQuads scans for the dotted-quad regexes:
//
//	strict (ipv4Pattern): \b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
//	loose  (audit rule):  \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
//
// An octet is always a whole run of digits: the first three must be followed
// directly by '.', the last by \b, and a shorter prefix of a run is followed
// by another digit. The strict octet alternation accepts exactly the 1-2
// digit runs and the 3-digit runs <= 255.
func findDottedQuads(line string, strict bool) [][2]int {
	var out [][2]int
	for i := 0; i < len(line); i++ {
		if !isDigitByte(line[i]) || !wordBoundaryBefore(line, i) {
			continue
		}
		if end, ok := matchDottedQuad(line, i, strict); ok {
			out = append(out, [2]int{i, end})
			i = end - 1
		}
	}
	return out
}

func matchDottedQuad(line string, i int, strict bool) (int, bool) {
	for octet := 0; octet < 4; octet++ {
		end := digitRunEnd(line, i)
		n := end - i
		if n == 0 || n > 3 {
			return 0, false
		}
		if strict && n == 3 && (int(line[i]-'0')*100+int(line[i+1]-'0')*10+int(line[i+2]-'0')) > 255 {
			return 0, false
		}
		if octet == 3 {
			return end, wordBoundaryAfter(line, end)
		}
		if end >= len(line) || line[end] != '.' {
			return 0, false
		}
		i = end + 1
	}
	return 0, false // unreachable
}

// FindDottedQuads returns every \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3} span with
// word boundaries on both ends (octets not range-checked). For the audit
// scanner's unredacted-ipv4 rule.
func FindDottedQuads(line string) [][2]int { return findDottedQuads(line, false) }

// uuidGroups are the hex-digit group lengths of an 8-4-4-4-12 UUID.
var uuidGroups = [5]int{8, 4, 4, 4, 12}

// findUUIDs scans for uuidPattern:
// \b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b
func findUUIDs(line string) [][2]int {
	var out [][2]int
	for i := 0; i+36 <= len(line); i++ {
		if !isHexByte(line[i]) || !wordBoundaryBefore(line, i) {
			continue
		}
		if end, ok := matchUUID(line, i); ok {
			out = append(out, [2]int{i, end})
			i = end - 1
		}
	}
	return out
}

func matchUUID(line string, i int) (int, bool) {
	for g, n := range uuidGroups {
		if g > 0 {
			if line[i] != '-' {
				return 0, false
			}
			i++
		}
		for k := 0; k < n; k++ {
			if !isHexByte(line[i+k]) {
				return 0, false
			}
		}
		i += n
	}
	return i, wordBoundaryAfter(line, i)
}

func isAlnumByte(c byte) bool { return isDigitByte(c) || isASCIILetter(c) }

// FindFQDNCandidates scans for fqdnPattern (shared with the audit pass):
//
//	\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b
//
// The regex has no real choices to backtrack over. A label consumes only
// [a-zA-Z0-9-] and must be followed by '.', so each label\. iteration takes
// the whole [a-zA-Z0-9-] run up to the next byte, which must be '.'. The
// final [a-zA-Z]{2,}\b can only end where the letter run ends (inside the
// run the next byte is a word character). So from a start, the labels form
// one fixed chain, and the greedy + means the longest prefix of that chain
// followed by a valid TLD wins.
func FindFQDNCandidates(line string) [][2]int {
	if strings.IndexByte(line, '.') < 0 {
		return nil
	}
	var out [][2]int
	for i := 0; i < len(line); i++ {
		if !isAlnumByte(line[i]) || !wordBoundaryBefore(line, i) {
			continue
		}
		if end, ok := matchFQDN(line, i); ok {
			out = append(out, [2]int{i, end})
			i = end - 1
		}
	}
	return out
}

// matchFQDN returns the end of the fqdnPattern match starting at i, if any.
func matchFQDN(line string, i int) (int, bool) {
	best := -1
	p := i
	for {
		// One label\. iteration starting at p.
		q := p
		for q < len(line) && (isAlnumByte(line[q]) || line[q] == '-') {
			q++
		}
		if q == len(line) || line[q] != '.' || q-p > 63 || !isAlnumByte(line[p]) || !isAlnumByte(line[q-1]) {
			break
		}
		p = q + 1
		// A TLD right after this dot: a whole letter run of 2+ ending at \b.
		e := p
		for e < len(line) && isASCIILetter(line[e]) {
			e++
		}
		if e-p >= 2 && wordBoundaryAfter(line, e) {
			best = e // a later (longer) chain overrides this one
		}
		if p == len(line) {
			break
		}
	}
	return best, best >= 0
}

// FindMACs scans for macPattern (shared with the audit pass):
//
//	\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b
//
// Every piece has a fixed length, so a match from a start is all or nothing.
func FindMACs(line string) [][2]int {
	var out [][2]int
	for i := 0; i+17 <= len(line); i++ {
		if !isHexByte(line[i]) || !wordBoundaryBefore(line, i) {
			continue
		}
		if matchMAC(line, i) {
			out = append(out, [2]int{i, i + 17})
			i += 16
		}
	}
	return out
}

func matchMAC(line string, i int) bool {
	for g := 0; g < 6; g++ {
		p := i + 3*g
		if !isHexByte(line[p]) || !isHexByte(line[p+1]) {
			return false
		}
		if g < 5 && line[p+2] != ':' && line[p+2] != '-' {
			return false
		}
	}
	return wordBoundaryAfter(line, i+17)
}

// urlSchemes are urlPattern's literal schemes (jdbc:[a-z]+ is handled
// separately).
var urlSchemes = []string{"http", "https", "ftp", "ftps", "sftp", "tcp", "ssl", "nio", "amqp", "amqps", "mqtt", "ldap", "ldaps"}

// isURLTailByte is urlPattern's tail class [^\s<>"',;)] (all ASCII, so a
// byte test agrees with RE2's rune test, invalid UTF-8 included).
func isURLTailByte(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\f', '\r', '<', '>', '"', '\'', ',', ';', ')':
		return false
	}
	return true
}

// findURLs scans for urlPattern:
//
//	(?:https?|ftps?|sftp|jdbc:[a-z]+|tcp|ssl|nio|amqps?|mqtt|ldaps?)://[^\s<>"',;)]+
//
// Every match contains "://", so the scan jumps between those. A scheme
// holds no '/', so it lies between the previous "://" (or the end of the
// previous match) and this one, and must end exactly at it; the leftmost
// scheme start wins, as in the regex. The tail is a single greedy class
// that must take at least one byte.
func findURLs(line string) [][2]int {
	var out [][2]int
	from := 0 // where the regex would resume searching
	for c := 0; ; {
		k := strings.Index(line[c:], "://")
		if k < 0 {
			return out
		}
		c += k
		start := -1
		for _, sch := range urlSchemes {
			if p := c - len(sch); p >= from && (start < 0 || p < start) && line[p:c] == sch {
				start = p
			}
		}
		// jdbc:[a-z]+ -- the letters must start right after "jdbc:".
		a := c
		for a > from && line[a-1] >= 'a' && line[a-1] <= 'z' {
			a--
		}
		if a < c && a-5 >= from && line[a-5:a] == "jdbc:" && (start < 0 || a-5 < start) {
			start = a - 5
		}
		e := c + 3
		for e < len(line) && isURLTailByte(line[e]) {
			e++
		}
		if start < 0 || e == c+3 {
			c++
			continue
		}
		out = append(out, [2]int{start, e})
		from, c = e, e
	}
}

// isIPv6CoreByte is ipv6Core's class: [0-9a-fA-F:.]
func isIPv6CoreByte(c byte) bool { return isHexByte(c) || c == ':' || c == '.' }

// findIPv6Candidates scans for ipv6Core ([0-9a-fA-F:.]+): every maximal run
// of the class. Runs with fewer than two colons are dropped here rather than
// returned, since IPv6Detector discards them anyway.
func findIPv6Candidates(line string) [][2]int {
	var out [][2]int
	for i := 0; i < len(line); {
		if !isIPv6CoreByte(line[i]) {
			i++
			continue
		}
		start, colons := i, 0
		for i < len(line) && isIPv6CoreByte(line[i]) {
			if line[i] == ':' {
				colons++
			}
			i++
		}
		if colons >= 2 {
			out = append(out, [2]int{start, i})
		}
	}
	return out
}

// casTicketPrefixes are casTicketPattern's alternatives, each with its '-'.
// No two can match at the same position (their first two bytes differ).
var casTicketPrefixes = [...]string{"ST-", "PT-", "TGT-", "PGT-"}

func isCASTicketTailByte(c byte) bool {
	return isRE2WordChar(c) || c == '.' || c == '-' // [A-Za-z0-9._-]
}

// findCASTickets scans for casTicketPattern:
// \b(?:ST|PT|TGT|PGT)-\d+-[A-Za-z0-9._-]+
func findCASTickets(line string) [][2]int {
	var out [][2]int
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c != 'S' && c != 'P' && c != 'T' || !wordBoundaryBefore(line, i) {
			continue
		}
		if end, ok := matchCASTicket(line, i); ok {
			out = append(out, [2]int{i, end})
			i = end - 1
		}
	}
	return out
}

func matchCASTicket(line string, i int) (int, bool) {
	j := -1
	for _, p := range casTicketPrefixes {
		if len(line)-i >= len(p) && line[i:i+len(p)] == p {
			j = i + len(p)
			break
		}
	}
	if j < 0 {
		return 0, false
	}
	k := digitRunEnd(line, j)
	if k == j || k >= len(line) || line[k] != '-' {
		return 0, false
	}
	k++
	end := k
	for end < len(line) && isCASTicketTailByte(line[end]) {
		end++
	}
	return end, end > k
}

// isParamValueByte is paramValue's class: [^&\s"'#;,<>)]
func isParamValueByte(c byte) bool {
	switch c {
	case '&', ' ', '\t', '\n', '\f', '\r', '"', '\'', '#', ';', ',', '<', '>', ')':
		return false
	}
	return true
}

// findParamValues scans an ASCII-only line for the value spans (group 1) of
//
//	secretParamPattern    (needSep false): (?i)\b(?:<names>)=<value>
//	ambiguousParamPattern (needSep true):  (?i)[?&;](?:<names>)=<value>
//
// where keys holds the lowercased names. The name is always the whole ASCII
// word directly before an '=': it must be followed by '=', and is preceded
// by \b or by one of [?&;], neither of which is a word character. Callers
// must use the regex instead on a line with non-ASCII bytes (see the file
// comment).
func findParamValues(line string, keys map[string]bool, needSep bool) [][2]int {
	var out [][2]int
	lastEnd := 0
	for i := 0; i < len(line); i++ {
		if line[i] != '=' {
			continue
		}
		s := i
		for s > 0 && isRE2WordChar(line[s-1]) {
			s--
		}
		if s == i || !keys[asciiLower(line[s:i])] {
			continue
		}
		matchStart := s
		if needSep {
			if s == 0 {
				continue
			}
			if c := line[s-1]; c != '?' && c != '&' && c != ';' {
				continue
			}
			matchStart = s - 1
		}
		if matchStart < lastEnd {
			continue
		}
		end := i + 1
		for end < len(line) && isParamValueByte(line[end]) {
			end++
		}
		if end == i+1 {
			continue
		}
		out = append(out, [2]int{i + 1, end})
		lastEnd = end
		i = end - 1
	}
	return out
}

// hasVersionKeywordSuffix reports whether ipv4VersionKeyword
// ((?i)\b(?:v|version|release|sas)\s*[:=]?\s*$) matches prefix: trailing
// whitespace, at most one ':' or '=', more whitespace, and before that a
// whole word that is one of the keywords.
func hasVersionKeywordSuffix(prefix string) bool {
	end := trimRE2SpaceRight(prefix, len(prefix))
	if end > 0 && (prefix[end-1] == ':' || prefix[end-1] == '=') {
		end = trimRE2SpaceRight(prefix, end-1)
	}
	start := end
	for start > 0 && (isRE2WordChar(prefix[start-1]) || prefix[start-1] >= 0x80) {
		start--
	}
	word := prefix[start:end]
	if hasNonASCII(word) {
		// A case-folded non-ASCII letter ("ſas") may be part of the keyword.
		return ipv4VersionKeyword.MatchString(prefix)
	}
	switch asciiLower(word) {
	case "v", "version", "release", "sas":
		return true
	}
	return false
}

// redactSpans turns spans into whole-value redactions (see redactWhole).
func redactSpans(line string, spans [][2]int) []Match {
	var matches []Match
	for _, sp := range spans {
		matches = append(matches, Match{
			Span:   Span{Start: sp[0], End: sp[1]},
			Value:  line[sp[0]:sp[1]],
			Redact: true,
		})
	}
	return matches
}

func trimRE2SpaceRight(s string, end int) int {
	for end > 0 && isRE2Space(s[end-1]) {
		end--
	}
	return end
}
